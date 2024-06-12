/*
 Generated by typeshare 1.9.2
*/

/** Logo to display on the credential */
export interface Logo {
	/** Base64 encoded image */
	image: string;
	/** Image media type */
	media_type: string;
}

/** Summary view for a verifiable credential */
export interface CredentialDisplay {
	/** Credential ID */
	id: string;
	/** CSS color to use for the background of a credential display */
	background_color?: string;
	/** CSS color to use for the text of a credential display */
	color?: string;
	/** Label to display on the credential to indicate the issuer */
	issuer?: string;
	/** Logo to display on the credential */
	logo?: Logo;
	/** URL of the original source of the logo */
	logo_url?: string;
	/** Name of the credential */
	name?: string;
}

/** View model for the credential sub-app */
export interface CredentialView {
	/** List of credentials */
	credentials: CredentialDisplay[];
}

/** Detail view for a verifiable credential */
export interface CredentialDetail {
	/** Display */
	display: CredentialDisplay;
	/** Issuance date */
	issuance_date: string;
	/** Expiry */
	expiration_date?: string;
	/** Description */
	description?: string;
	/** Claims */
	claims: Record<string, string>;
}

/** Status of the issuance flow */
export enum IssuanceStatus {
	/** No credential offer is being processed. */
	Inactive = "Inactive",
	/** A new credential offer has been received. */
	Offered = "Offered",
	/** Metadata has been retrieved and the offer is ready to be viewed. */
	Ready = "Ready",
	/** The offer requires a user pin to progress. */
	PendingPin = "PendingPin",
	/** The offer has been accepted and the credential is being issued. */
	Accepted = "Accepted",
	/** A credential has been requested. */
	Requested = "Requested",
	/** The credential offer has failed, with an error message. */
	Failed = "Failed",
}

/** Issuance flow viewable state */
export interface IssuanceView {
	/** Credential offer status */
	status: IssuanceStatus;
	/** Credentials on offer */
	credentials: Record<string, CredentialDisplay>;
	/** PIN */
	pin?: string;
}

/** Types of PIN characters */
export enum PinInputMode {
	/** Only digits */
	Numeric = "Numeric",
	/** Any characters */
	Text = "Text",
}

/** Criteria for PIN */
export interface PinSchema {
	/** Input mode for the PIN */
	input_mode: PinInputMode;
	/**
	 * Specifies the length of the PIN. This helps the Wallet to render
	 * the input screen and improve the user experience.
	 */
	length: number;
	/** Guidance for the Holder of the Wallet on how to obtain the Transaction Code, */
	description?: string;
}

/** Status of the presentation flow */
export enum PresentationStatus {
	/** No authorization request is being processed. */
	Inactive = "Inactive",
	/** A new authorization request has been received. */
	Requested = "Requested",
	/** The authorization request has been authorized. */
	Authorized = "Authorized",
	/** The authorization request has failed, with an error message. */
	Failed = "Failed",
}

/** Presentation flow viewable state */
export interface PresentationView {
	/** Presentation request status */
	status: PresentationStatus;
	/** Credentials to present */
	credentials: Record<string, CredentialDisplay>;
}

export enum SubApp {
	Splash = "Splash",
	Credential = "Credential",
	Issuance = "Issuance",
	Presentation = "Presentation",
}

export interface ViewModel {
	sub_app: SubApp;
	credential?: CredentialView;
	issuance?: IssuanceView;
	presentation?: PresentationView;
	/** Error message, if any */
	error?: string;
}

