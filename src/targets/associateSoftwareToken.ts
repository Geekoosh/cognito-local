import type {
  AssociateSoftwareTokenRequest,
  AssociateSoftwareTokenResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import jwt from "jsonwebtoken";
import { NotAuthorizedError, SoftwareTokenMFANotFoundError } from "../errors";
import type { Services } from "../services";
import type { Token } from "../services/tokenGenerator";
import { generateSecret } from "../services/totp";
import { validateMfaAuthorization } from "./mfaValidation";
import type { Target } from "./Target";

export type AssociateSoftwareTokenTarget = Target<
  AssociateSoftwareTokenRequest,
  AssociateSoftwareTokenResponse
>;

type AssociateSoftwareTokenServices = Pick<Services, "cognito" | "sessions">;

export const AssociateSoftwareToken =
  ({
    cognito,
    sessions,
  }: AssociateSoftwareTokenServices): AssociateSoftwareTokenTarget =>
  async (ctx, req) => {
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

      const secret = generateSecret();
      await userPool.saveUser(ctx, {
        ...user,
        SoftwareTokenMfaConfiguration: {
          Secret: secret,
          Verified: false,
        },
      });

      const rotatedSession = sessions.rotate(req.Session as string);
      if (!rotatedSession) {
        throw new NotAuthorizedError("Invalid session for the user.");
      }

      return {
        SecretCode: secret,
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

    const secret = generateSecret();
    await userPool.saveUser(ctx, {
      ...user,
      SoftwareTokenMfaConfiguration: {
        Secret: secret,
        Verified: false,
      },
    });

    return {
      SecretCode: secret,
    };
  };
