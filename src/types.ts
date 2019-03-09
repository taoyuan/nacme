export interface Jwk {
  e: string;
  kty: string;
  n: string;
}

export interface DomainNames {
  commonName: string;
  altNames: string[];
}

export interface CertificateInfo {
  domains: DomainNames;
  notBefore?: Date;
  notAfter?: Date;
}

export interface AcmeIdentifier {
  type: string;
  value: string;
}

export interface AcmeChallenge {
  type: string;
  token: string;
  status: string;
  url: string;
}

export interface AcmeAuthorization {
  identifier: AcmeIdentifier;
  url: string;
  expires: string;
  status: string;
  challenges: AcmeChallenge[];
  wildcard: boolean;
}

export interface AcmeAccount {
  id: number;
  status: string;
  contact: string[];
  key: {
    kty: string;
    [name: string]: any;
  },
  initialIp: string;
  createdAt: string;
}

export interface AcmeOrder {
  url: string;
  status: string;
  expires: string;
  identifiers: AcmeIdentifier[];
  notBefore: string;
  notAfter: string;
  authorizations: string[];
  finalize: string;
  certificate: string;
  error?: any;
}
