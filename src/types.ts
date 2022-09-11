export interface IKeyParams {
  nonce: string;
  tag: string;
}

interface IAegisHeader {
  slots: AegisSlot[];
  params: IKeyParams;
}

interface IBaseSlot {
  type: number;
  uuid: string;
  key: string;
  key_params: IKeyParams;
}

interface IRawSlot extends IBaseSlot {
  type: 0;
}

interface IBiometricSlot extends IBaseSlot {
  type: 2;
}

interface IPasswordSlot extends IBaseSlot {
  type: 1;
  n: number;
  r: number;
  p: number;
  salt: string;
}

type AegisSlot = IRawSlot | IBiometricSlot | IPasswordSlot;

export interface IContent {
  version: 1;
  entries: {
    type: "totp" | "hotp";
    uuid: string;
    name: string;
    issuer: string;
    icon: string | null;
    info: {
      secret: string;
      algo?: "SHA1" | "SHA256" | "SHA512";
      digits?: number;
      period?: number;
    };
  }[];
}

export interface IEncryptedBackup {
  version: 1;
  header: IAegisHeader;
  db: string; // encrypted, decrypts to IContent
}
