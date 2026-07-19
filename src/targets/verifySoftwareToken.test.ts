import jwt from "jsonwebtoken";
import * as uuid from "uuid";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockSessionService } from "../__tests__/mockSessionService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
  SoftwareTokenMFANotFoundError,
} from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { SessionService, UserPoolService } from "../services";
import { generate, generateSecret } from "../services/totp";
import {
  VerifySoftwareToken,
  type VerifySoftwareTokenTarget,
} from "./verifySoftwareToken";

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

describe("VerifySoftwareToken target", () => {
  let verifySoftwareToken: VerifySoftwareTokenTarget;
  let mockSessions: MockedObject<SessionService>;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService({
      Id: "pool",
      SoftwareTokenMfaConfiguration: { Enabled: true },
    });
    mockSessions = newMockSessionService();
    verifySoftwareToken = VerifySoftwareToken({
      cognito: newMockCognitoService(mockUserPoolService),
      sessions: mockSessions,
    });
  });

  it.each(["1234", "abcdef", "12345a", "1234567"])(
    "rejects malformed UserCode %j",
    async (userCode) => {
      await expect(
        verifySoftwareToken(TestContext, {
          AccessToken: signAccessToken("user"),
          UserCode: userCode,
        }),
      ).rejects.toEqual(
        new InvalidParameterError("UserCode must be a 6-digit number."),
      );
      expect(mockUserPoolService.getUserByUsername).not.toHaveBeenCalled();
    },
  );

  it("rejects when both AccessToken and Session are provided", async () => {
    await expect(
      verifySoftwareToken(TestContext, {
        AccessToken: signAccessToken("user"),
        Session: "valid-session-token-123",
        UserCode: "123456",
      }),
    ).rejects.toEqual(
      new InvalidParameterError(
        "Exactly one of AccessToken or Session must be provided",
      ),
    );
  });

  it("verifies a correct code and marks the secret verified", async () => {
    const secret = generateSecret();
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: secret, Verified: false },
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const result = await verifySoftwareToken(TestContext, {
      AccessToken: signAccessToken(user.Username),
      UserCode: generate(secret),
      FriendlyDeviceName: "iPhone",
    });

    expect(result.Status).toBe("SUCCESS");
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        SoftwareTokenMfaConfiguration: {
          Secret: secret,
          Verified: true,
          FriendlyDeviceName: "iPhone",
        },
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
      }),
    );
    expect(mockSessions.get).not.toHaveBeenCalled();
  });

  it("rejects a wrong code", async () => {
    const secret = generateSecret();
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: secret, Verified: false },
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      verifySoftwareToken(TestContext, {
        AccessToken: signAccessToken(user.Username),
        UserCode: "000000",
      }),
    ).rejects.toBeInstanceOf(CodeMismatchError);
    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });

  it("rejects when the user has no associated secret", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      verifySoftwareToken(TestContext, {
        AccessToken: signAccessToken(user.Username),
        UserCode: "123456",
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("verifies a code and rotates an MFA_SETUP session", async () => {
    const secret = generateSecret();
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: secret, Verified: false },
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    mockSessions.get.mockReturnValue({
      clientId: "client",
      expiresAt: Date.now() + 60_000,
      purpose: "MFA_SETUP",
      userPoolId: "pool",
      username: user.Username,
    });
    mockSessions.rotate.mockReturnValue("rotated-session");

    const result = await verifySoftwareToken(TestContext, {
      Session: "associated-session-token-123",
      UserCode: generate(secret),
    });

    expect(result).toEqual({
      Status: "SUCCESS",
      Session: "rotated-session",
    });
    expect(mockSessions.rotate).toHaveBeenCalledWith(
      "associated-session-token-123",
    );
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        SoftwareTokenMfaConfiguration: {
          Secret: secret,
          Verified: true,
          FriendlyDeviceName: undefined,
        },
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
      }),
    );
  });

  it("rejects an invalid MFA_SETUP session", async () => {
    mockSessions.get.mockReturnValue(null);

    await expect(
      verifySoftwareToken(TestContext, {
        Session: "invalid-session-token-123",
        UserCode: "123456",
      }),
    ).rejects.toEqual(new NotAuthorizedError("Invalid session for the user."));
    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });

  it("rejects verification when TOTP is disabled for the pool", async () => {
    const secret = generateSecret();
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: secret, Verified: false },
    });
    mockUserPoolService.options.SoftwareTokenMfaConfiguration = undefined;
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      verifySoftwareToken(TestContext, {
        AccessToken: signAccessToken(user.Username),
        UserCode: generate(secret),
      }),
    ).rejects.toEqual(new SoftwareTokenMFANotFoundError());
    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });
});
