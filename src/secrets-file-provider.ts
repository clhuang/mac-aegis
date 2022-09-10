import * as ElectronStore from "electron-store";
import fs from "fs";
import { IEncryptedBackup } from "./types";

export class InvalidSecretsPathError extends Error {
  constructor() {
    super(`No secrets location specified`);
  }
}

export class SecretsFileProvider {
  private secrets: IEncryptedBackup;
  constructor(private store: ElectronStore) {}

  hasValidSecretsPath(): boolean {
    const secretsPath = this.store.get("secrets-path") as string;
    if (secretsPath == null) return false;
    return fs.existsSync(secretsPath);
  }

  setSecretsPath(path: string): void {
    this.store.set("secrets-path", path);
    this.secrets = null;
  }

  async loadSecrets() {
    const secretsPath = this.store.get("secrets-path") as string;
    if (secretsPath == null) {
      throw new InvalidSecretsPathError();
    }
    this.secrets = JSON.parse(await fs.promises.readFile(secretsPath, "utf8"));
  }

  getContents() {
    return this.secrets;
  }
}
