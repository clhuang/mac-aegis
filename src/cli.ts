import fs from "fs";
import { decrypt } from "./decrypt";
import prompts from "prompts";
import totp from "totp-generator";
import { IEncryptedBackup } from "./types";

async function readBackupContents(filename: string) {
  return JSON.parse(await fs.promises.readFile(filename, "utf8"));
}

async function main() {
  if (!process.argv[2]) {
    console.log(`Usage: ${process.argv[1]} path-to-backup.json.aes`);
    return;
  }
  const contents: IEncryptedBackup = await readBackupContents(process.argv[2]);
  const { password } = await prompts({
    type: "password",
    name: "password",
    message: "Enter your password",
  });
  const decrypted = await decrypt(password, contents);
  const choices = decrypted.entries.map((s, i) => ({
    title: `${s.issuer} – ${s.name}`,
  }));
  const { i } = await prompts({
    type: "select",
    name: "i",
    choices,
    message: "Pick a service",
  });
  const entry = decrypted.entries[i];
  const otp = totp(entry.info.secret, {
    digits: entry.info.digits,
    period: entry.info.period,
  });
  console.log(otp);
}

main();
