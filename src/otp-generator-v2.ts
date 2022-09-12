import { workerData, parentPort } from "worker_threads";
import keytar from "keytar";
import totp from "totp-generator";
import * as crypto from "crypto";
import { IContent, IEncryptedBackup, IKeyParams } from "./types";
import { WorkerJob } from "./otp-generator";

const data = workerData as WorkerJob;

(async () => {
  switch (data.type) {
    case "init": {
      const backupInfo = parseBackupFile(data.backup);
      const key = await deriveKey(
        data.password,
        backupInfo.n,
        backupInfo.r,
        backupInfo.p,
        backupInfo.salt
      );
      const masterKey = decryptMasterKey(
        key,
        backupInfo.key,
        backupInfo.slotKeyParams
      );
      await storeMasterKey(masterKey, Buffer.from(data.ephemeralKey, "hex"));
      const plainText = decryptPayload(
        backupInfo.payload,
        masterKey,
        backupInfo.keyParams
      );
      const serviceInfo: IContent = JSON.parse(plainText.toString());
      parentPort.postMessage({
        serviceList: getServiceList(serviceInfo),
      });
      break;
    }
    case "genotp": {
      const masterKey = await retrieveMasterKey(
        Buffer.from(data.ephemeralKey, "hex")
      );
      const backupInfo = parseBackupFile(data.backup);
      const plainText = decryptPayload(
        backupInfo.payload,
        masterKey,
        backupInfo.keyParams
      );
      const serviceInfo: IContent = JSON.parse(plainText.toString());
      const service = serviceInfo.entries.find(
        (s) => s.issuer === data.issuer && s.name === data.label
      );
      if (service == null) {
        throw new Error("Service not found");
      }

      const period = service.info.period ?? 30;

      const otp = totp(service.info.secret, {
        digits: service.info.digits,
        algorithm: translateHashAlgorithm(service.info.algo),
        period,
      });
      parentPort.postMessage({
        otp,
        serviceList: getServiceList(serviceInfo),
        remainingMs: expiresIn(period),
      });
    }
  }
})();

async function storeMasterKey(
  masterKey: Buffer,
  ephemeralKey: Buffer // TODO use secure enclave?
): Promise<void> {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ephemeralKey, nonce);
  const encrypted = Buffer.concat([
    nonce,
    cipher.update(masterKey),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  await keytar.setPassword("mac-aegis", "ephemeral", encrypted.toString("hex"));
}

async function retrieveMasterKey(ephemeralKey: Buffer): Promise<Buffer> {
  const data = Buffer.from(
    await keytar.getPassword("mac-aegis", "ephemeral"),
    "hex"
  );
  const tagOffset = data.length - 16;
  const nonce = data.subarray(0, 12);
  const encryptedKey = data.subarray(12, tagOffset);
  const tag = data.subarray(tagOffset);
  const decrypt = crypto.createDecipheriv("aes-256-gcm", ephemeralKey, nonce);
  decrypt.setAuthTag(tag);
  return Buffer.concat([decrypt.update(encryptedKey), decrypt.final()]);
}

function getServiceList(serviceInfo: IContent) {
  return serviceInfo.entries.map((x) => ({
    issuer: x.issuer,
    label: x.name,
    thubnail: x.icon,
  }));
}

function parseBackupFile(backup: IEncryptedBackup) {
  const slot = (() => {
    for (const slot of backup.header.slots) {
      if (slot.type === 1) return slot;
    }
    throw new Error("No password-encrypted slot found");
  })();

  return {
    n: slot.n,
    r: slot.r,
    p: slot.p,
    salt: Buffer.from(slot.salt, "hex"),
    key: Buffer.from(slot.key, "hex"),
    slotKeyParams: slot.key_params,
    keyParams: backup.header.params,
    payload: Buffer.from(backup.db, "base64"),
  };
}

function deriveKey(
  password: string,
  n: number,
  r: number,
  p: number,
  salt: Buffer
) {
  return new Promise<Buffer>((res, rej) => {
    crypto.scrypt(
      password,
      salt,
      32,
      { N: n, r, p, maxmem: 256 * n * r },
      (err, result) => (err ? rej(err) : res(result))
    );
  });
}

function decryptMasterKey(
  derivedKey: Buffer,
  encryptedKey: Buffer,
  keyParams: IKeyParams
) {
  const decrypt = crypto.createDecipheriv(
    "aes-256-gcm",
    derivedKey,
    Buffer.from(keyParams.nonce, "hex")
  );
  decrypt.setAuthTag(Buffer.from(keyParams.tag, "hex"));
  return Buffer.concat([decrypt.update(encryptedKey), decrypt.final()]);
}

function decryptPayload(
  payload: Buffer,
  masterKey: Buffer,
  keyParams: IKeyParams
) {
  const decrypt = crypto.createDecipheriv(
    "aes-256-gcm",
    masterKey,
    Buffer.from(keyParams.nonce, "hex")
  );
  decrypt.setAuthTag(Buffer.from(keyParams.tag, "hex"));
  return Buffer.concat([decrypt.update(payload), decrypt.final()]);
}

function translateHashAlgorithm(format: string = "SHA-1"): string {
  switch (format) {
    case "SHA1":
      return "SHA-1";
    case "SHA256":
      return "SHA-256";
    case "SHA512":
      return "SHA-512";
    default:
      return format;
  }
}

function expiresIn(period: number): number {
  const periodMs = period * 1000;
  const epoch = Date.now();
  const elapsed = epoch % periodMs;
  const remaining = periodMs - elapsed;
  return remaining;
}
