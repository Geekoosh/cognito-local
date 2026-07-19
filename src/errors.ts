export class UnsupportedError extends Error {}

export class CognitoError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.code = `${code}`;
  }
}

export class NotAuthorizedError extends CognitoError {
  public constructor(message = "User not authorized") {
    super("NotAuthorizedException", message);
  }
}

export class UserNotFoundError extends CognitoError {
  public constructor(message = "User not found.") {
    super("UserNotFoundException", message);
  }
}

export class UsernameExistsError extends CognitoError {
  public constructor() {
    super("UsernameExistsException", "User already exists");
  }
}

export class CodeMismatchError extends CognitoError {
  public constructor() {
    super("CodeMismatchException", "Incorrect confirmation code");
  }
}

export class ExpiredCodeError extends CognitoError {
  public constructor() {
    super(
      "ExpiredCodeException",
      "Invalid code provided, please request a code again.",
    );
  }
}

export class InvalidPasswordError extends CognitoError {
  public constructor() {
    super("InvalidPasswordException", "Invalid password");
  }
}

export class PasswordResetRequiredError extends CognitoError {
  public constructor() {
    super("PasswordResetRequiredException", "Password reset required");
  }
}

export class UserNotConfirmedException extends CognitoError {
  public constructor() {
    super("UserNotConfirmedException", "User is not confirmed.");
  }
}

export class ResourceNotFoundError extends CognitoError {
  public constructor(message?: string) {
    super("ResourceNotFoundException", message ?? "Resource not found");
  }
}

export class GroupNotFoundError extends ResourceNotFoundError {
  public constructor() {
    super("Group not found");
  }
}

export class UnexpectedLambdaExceptionError extends CognitoError {
  public constructor() {
    super(
      "UnexpectedLambdaExceptionException",
      "Unexpected error when invoking lambda",
    );
  }
}

export class UserLambdaValidationError extends CognitoError {
  public constructor(message?: string) {
    super(
      "UserLambdaValidationException",
      message ?? "Lambda threw an exception",
    );
  }
}

export class InvalidLambdaResponseError extends CognitoError {
  public constructor() {
    super("InvalidLambdaResponseException", "Invalid Lambda response");
  }
}

export class InvalidParameterError extends CognitoError {
  public constructor(message = "Invalid parameter") {
    super("InvalidParameterException", message);
  }
}

export class InvalidUserPoolConfigurationError extends CognitoError {
  public constructor(message = "Invalid user pool configuration.") {
    super("InvalidUserPoolConfigurationException", message);
  }
}

export class SoftwareTokenMFANotFoundError extends CognitoError {
  public constructor(
    message = "Software token MFA is not enabled for the user pool.",
  ) {
    super("SoftwareTokenMFANotFoundException", message);
  }
}

export class OperationNotEnabledError extends CognitoError {
  public constructor(
    message = "The requested operation is not enabled for this user pool.",
  ) {
    super("OperationNotEnabledException", message);
  }
}

export class MFAMethodNotFoundError extends CognitoError {
  public constructor(message = "MFA method not found.") {
    super("MFAMethodNotFoundException", message);
  }
}
