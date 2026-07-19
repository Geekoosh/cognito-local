import jwt from "jsonwebtoken";
import * as uuid from "uuid";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, OperationNotEnabledError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { UserPoolService } from "../services";
import {
  SetUserMFAPreference,
  type SetUserMFAPreferenceTarget,
} from "./setUserMFAPreference";

const signAccessToken = (sub: string) =>
  jwt.sign(
    {
      sub,
      event_id: "0",
      token_use: "access",
      scope: "aws.cognito.signin.user.admin",
      auth_time: new Date(),
      jti: uuid.v4(),
      client_id: "test",
      username: sub,
    },
    PrivateKey.pem,
    {
      algorithm: "RS256",
      issuer: "http://localhost:9229/test",
      expiresIn: "24h",
      keyid: "CognitoLocal",
    },
  );

describe("SetUserMFAPreference target", () => {
  let setUserMFAPreference: SetUserMFAPreferenceTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService({
      Id: "pool",
      MfaConfiguration: "OPTIONAL",
      SmsConfiguration: {
        SnsCallerArn: "arn:aws:iam::000000000000:role/test",
      },
      SoftwareTokenMfaConfiguration: { Enabled: true },
    });
    setUserMFAPreference = SetUserMFAPreference({
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("enables SMS_MFA and marks it preferred", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await setUserMFAPreference(TestContext, {
      AccessToken: signAccessToken(user.Username),
      SMSMfaSettings: { Enabled: true, PreferredMfa: true },
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        UserMFASettingList: ["SMS_MFA"],
        PreferredMfaSetting: "SMS_MFA",
      }),
    );
  });

  it("disables a previously-enabled method", async () => {
    const user = TDB.user({
      UserMFASettingList: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
      PreferredMfaSetting: "SMS_MFA",
      SoftwareTokenMfaConfiguration: {
        Secret: "SECRET",
        Verified: true,
      },
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await setUserMFAPreference(TestContext, {
      AccessToken: signAccessToken(user.Username),
      SMSMfaSettings: { Enabled: false },
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        PreferredMfaSetting: undefined,
      }),
    );
  });

  it("rejects enabling SOFTWARE_TOKEN_MFA without verified secret", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      setUserMFAPreference(TestContext, {
        AccessToken: signAccessToken(user.Username),
        SoftwareTokenMfaSettings: { Enabled: true },
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("accepts enabling SOFTWARE_TOKEN_MFA when secret is verified", async () => {
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: "s", Verified: true },
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await setUserMFAPreference(TestContext, {
      AccessToken: signAccessToken(user.Username),
      SoftwareTokenMfaSettings: { Enabled: true, PreferredMfa: true },
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
      }),
    );
  });

  it("rejects multiple preferred MFA methods", async () => {
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: "s", Verified: true },
      UserMFASettingList: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      setUserMFAPreference(TestContext, {
        AccessToken: signAccessToken(user.Username),
        SMSMfaSettings: { PreferredMfa: true },
        SoftwareTokenMfaSettings: { PreferredMfa: true },
      }),
    ).rejects.toEqual(
      new InvalidParameterError("Only one MFA method can be set as preferred."),
    );
  });

  it("preserves an existing preference when PreferredMfa is omitted", async () => {
    const user = TDB.user({
      PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
      SoftwareTokenMfaConfiguration: { Secret: "s", Verified: true },
      UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await setUserMFAPreference(TestContext, {
      AccessToken: signAccessToken(user.Username),
      SoftwareTokenMfaSettings: { Enabled: true },
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
      }),
    );
  });

  it("rejects disabling an enrolled method when MFA is required", async () => {
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: "s", Verified: true },
      UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
    });
    mockUserPoolService.options.MfaConfiguration = "ON";
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      setUserMFAPreference(TestContext, {
        AccessToken: signAccessToken(user.Username),
        SoftwareTokenMfaSettings: { Enabled: false },
      }),
    ).rejects.toEqual(
      new InvalidParameterError(
        "MFA methods cannot be disabled when MFA is required.",
      ),
    );
  });

  it("rejects enabling a method that is disabled for the pool", async () => {
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: "s", Verified: true },
    });
    mockUserPoolService.options.SoftwareTokenMfaConfiguration = undefined;
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      setUserMFAPreference(TestContext, {
        AccessToken: signAccessToken(user.Username),
        SoftwareTokenMfaSettings: { Enabled: true },
      }),
    ).rejects.toEqual(
      new OperationNotEnabledError(
        "Software token MFA is not enabled for the user pool.",
      ),
    );
  });
});
