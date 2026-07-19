import type {
  SMSMfaSettingsType,
  SoftwareTokenMfaSettingsType,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { InvalidParameterError, OperationNotEnabledError } from "../errors";
import type { User, UserPool } from "../services/userPoolService";

export const applyMfaPreferences = (
  user: User,
  userPool: UserPool,
  sms: SMSMfaSettingsType | undefined,
  software: SoftwareTokenMfaSettingsType | undefined,
): User => {
  if (sms?.PreferredMfa && software?.PreferredMfa) {
    throw new InvalidParameterError(
      "Only one MFA method can be set as preferred.",
    );
  }
  if ((sms?.Enabled || sms?.PreferredMfa) && !userPool.SmsConfiguration) {
    throw new OperationNotEnabledError(
      "SMS MFA is not enabled for the user pool.",
    );
  }
  if (
    (software?.Enabled || software?.PreferredMfa) &&
    !userPool.SoftwareTokenMfaConfiguration?.Enabled
  ) {
    throw new OperationNotEnabledError(
      "Software token MFA is not enabled for the user pool.",
    );
  }
  if (software?.Enabled && !user.SoftwareTokenMfaConfiguration?.Verified) {
    throw new InvalidParameterError("User has not verified software token MFA");
  }

  const methods = new Set(user.UserMFASettingList ?? []);
  if (
    userPool.MfaConfiguration === "ON" &&
    ((sms?.Enabled === false && methods.has("SMS_MFA")) ||
      (software?.Enabled === false && methods.has("SOFTWARE_TOKEN_MFA")))
  ) {
    throw new InvalidParameterError(
      "MFA methods cannot be disabled when MFA is required.",
    );
  }

  if (sms?.Enabled === true) methods.add("SMS_MFA");
  else if (sms?.Enabled === false) methods.delete("SMS_MFA");

  if (software?.Enabled === true) methods.add("SOFTWARE_TOKEN_MFA");
  else if (software?.Enabled === false) methods.delete("SOFTWARE_TOKEN_MFA");

  let preferred = user.PreferredMfaSetting;
  if (sms?.PreferredMfa) {
    preferred = "SMS_MFA";
  } else if (software?.PreferredMfa) {
    preferred = "SOFTWARE_TOKEN_MFA";
  } else if (
    (sms?.PreferredMfa === false && preferred === "SMS_MFA") ||
    (software?.PreferredMfa === false && preferred === "SOFTWARE_TOKEN_MFA")
  ) {
    preferred = undefined;
  }
  if (preferred && !methods.has(preferred)) {
    preferred = undefined;
  }

  if (
    (sms?.PreferredMfa && !methods.has("SMS_MFA")) ||
    (software?.PreferredMfa && !methods.has("SOFTWARE_TOKEN_MFA"))
  ) {
    throw new InvalidParameterError(
      "Cannot set an MFA method as preferred when it is not enabled.",
    );
  }

  return {
    ...user,
    UserMFASettingList: [...methods],
    PreferredMfaSetting: preferred,
  };
};
