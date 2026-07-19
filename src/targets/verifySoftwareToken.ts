import type {
  VerifySoftwareTokenRequest,
  VerifySoftwareTokenResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import jwt from "jsonwebtoken";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
  SoftwareTokenMFANotFoundError,
} from "../errors";
import type { Services } from "../services";
import type { Token } from "../services/tokenGenerator";
import { verify } from "../services/totp";
import {
  validateMfaAuthorization,
  validateTotpUserCode,
} from "./mfaValidation";
import type { Target } from "./Target";

export type VerifySoftwareTokenTarget = Target<
  VerifySoftwareTokenRequest,
  VerifySoftwareTokenResponse
>;

type VerifySoftwareTokenServices = Pick<Services, "cognito" | "sessions">;

export const VerifySoftwareToken =
  ({
    cognito,
    sessions,
  }: VerifySoftwareTokenServices): VerifySoftwareTokenTarget =>
  async (ctx, req) => {
    validateTotpUserCode(req.UserCode);
    validateMfaAuthorization(req.AccessToken, req.Session);

    if (!req.AccessToken) {
      const session = sessions.get(req.Session as string);
      if (!session || session.purpose !== "MFA_SETUP") {
        throw new NotAuthorizedError("Invalid session for the user.");
      }

      const userPool = await cognito.getUserPool(ctx, session.userPoolId);
      if (!userPool.options.SoftwareTokenMfaConfiguration?.Enabled) {
        throw new SoftwareTokenMFANotFoundError();
      }

      const user = await userPool.getUserByUsername(ctx, session.username);
      if (!user) {
        throw new NotAuthorizedError("Invalid session for the user.");
      }

      const secret = user.SoftwareTokenMfaConfiguration?.Secret;
      if (!secret) {
        throw new InvalidParameterError(
          "User has not associated a software token",
        );
      }

      if (!verify(secret, req.UserCode)) {
        throw new CodeMismatchError();
      }

      const existingMethods = user.UserMFASettingList ?? [];
      const UserMFASettingList = existingMethods.includes("SOFTWARE_TOKEN_MFA")
        ? existingMethods
        : [...existingMethods, "SOFTWARE_TOKEN_MFA"];

      await userPool.saveUser(ctx, {
        ...user,
        SoftwareTokenMfaConfiguration: {
          Secret: secret,
          Verified: true,
          FriendlyDeviceName:
            req.FriendlyDeviceName ??
            user.SoftwareTokenMfaConfiguration?.FriendlyDeviceName,
        },
        UserMFASettingList,
      });

      const rotatedSession = sessions.rotate(req.Session as string);
      if (!rotatedSession) {
        throw new NotAuthorizedError("Invalid session for the user.");
      }

      return {
        Status: "SUCCESS",
        Session: rotatedSession,
      };
    }

    const decoded = jwt.decode(req.AccessToken) as Token | null;
    if (!decoded) {
      throw new NotAuthorizedError("Invalid Access Token");
    }

    const userPool = await cognito.getUserPoolForClientId(
      ctx,
      decoded.client_id,
    );
    if (!userPool.options.SoftwareTokenMfaConfiguration?.Enabled) {
      throw new SoftwareTokenMFANotFoundError();
    }

    const user = await userPool.getUserByUsername(ctx, decoded.sub);
    if (!user) {
      throw new NotAuthorizedError();
    }

    const secret = user.SoftwareTokenMfaConfiguration?.Secret;
    if (!secret) {
      throw new InvalidParameterError(
        "User has not associated a software token",
      );
    }

    if (!verify(secret, req.UserCode)) {
      throw new CodeMismatchError();
    }

    const existingMethods = user.UserMFASettingList ?? [];
    const UserMFASettingList = existingMethods.includes("SOFTWARE_TOKEN_MFA")
      ? existingMethods
      : [...existingMethods, "SOFTWARE_TOKEN_MFA"];

    await userPool.saveUser(ctx, {
      ...user,
      SoftwareTokenMfaConfiguration: {
        Secret: secret,
        Verified: true,
        FriendlyDeviceName:
          req.FriendlyDeviceName ??
          user.SoftwareTokenMfaConfiguration?.FriendlyDeviceName,
      },
      UserMFASettingList,
    });

    return {
      Status: "SUCCESS",
      Session: req.Session,
    };
  };
