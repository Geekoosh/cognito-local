import { InvalidParameterError } from "../errors";

const SESSION_MIN_LENGTH = 20;
const SESSION_MAX_LENGTH = 2048;

export const validateMfaAuthorization = (
  accessToken: string | undefined,
  session: string | undefined,
): void => {
  if ((!accessToken && !session) || (accessToken && session)) {
    throw new InvalidParameterError(
      "Exactly one of AccessToken or Session must be provided",
    );
  }

  if (session) {
    validateMfaSession(session);
  }
};

export const validateMfaSession = (session: string): void => {
  if (
    session.length < SESSION_MIN_LENGTH ||
    session.length > SESSION_MAX_LENGTH ||
    /\s/.test(session)
  ) {
    throw new InvalidParameterError("Invalid session.");
  }
};

export const validateTotpUserCode = (userCode: string | undefined): void => {
  if (!userCode) {
    throw new InvalidParameterError("Missing required parameter UserCode");
  }
  if (!/^\d{6}$/.test(userCode)) {
    throw new InvalidParameterError("UserCode must be a 6-digit number.");
  }
};
