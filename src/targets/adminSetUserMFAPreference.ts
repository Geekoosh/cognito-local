import type {
  AdminSetUserMFAPreferenceRequest,
  AdminSetUserMFAPreferenceResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { applyMfaPreferences } from "./mfaPreferences";
import type { Target } from "./Target";

export type AdminSetUserMFAPreferenceTarget = Target<
  AdminSetUserMFAPreferenceRequest,
  AdminSetUserMFAPreferenceResponse
>;

type AdminSetUserMFAPreferenceServices = Pick<Services, "cognito">;

export const AdminSetUserMFAPreference =
  ({
    cognito,
  }: AdminSetUserMFAPreferenceServices): AdminSetUserMFAPreferenceTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError("User does not exist.");
    }

    await userPool.saveUser(
      ctx,
      applyMfaPreferences(
        user,
        userPool.options,
        req.SMSMfaSettings,
        req.SoftwareTokenMfaSettings,
      ),
    );

    return {};
  };
