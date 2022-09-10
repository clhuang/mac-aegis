import { SecretsFileProvider } from "./secrets-file-provider";
import { decrypt } from "./decrypt";
import totp from "totp-generator";
import { IContent } from "./types";

export interface ServiceInformation {
  issuer: string;
  label: string;
  thumbnail: string;
}

export interface Otp {
  otp: string;
  remainingMs: number;
}

export class OtpGenerator {
  private services: IContent = null;

  constructor(private secretsFileProvider: SecretsFileProvider) {}

  async unlock(password: string): Promise<void> {
    this.services = await decrypt(
      password,
      this.secretsFileProvider.getContents()
    );
  }

  lock(): void {
    this.services = null;
  }

  isUnlocked(): boolean {
    return this.services != null;
  }

  listServices(): ServiceInformation[] {
    // return [
    //   {label: "root@1234567890", issuer: "AWS", thumbnail: ""},
    //   {label: "user.name1", issuer: "Facebook", thumbnail: ""},
    //   {label: "example@gmail.com", issuer: "Google", thumbnail: ""},
    //   {label: "example@gmail.com", issuer: "Amazon", thumbnail: ""},
    // ];
    return this.services.entries.map((s) => ({
      issuer: s.issuer,
      label: s.name,
      thumbnail: s.icon,
    }));
  }

  async generateOTP(issuer: string, label: string): Promise<Otp> {
    const service = this.services.entries.find(
      (s) => s.issuer === issuer && s.name === label
    );
    if (service == null) {
      throw new Error("Service not found");
    }

    const period = service.info.period ?? 30;

    const otp = totp(service.info.secret, {
      digits: service.info.digits,
      algorithm: this.translateHashAlgorithm(service.info.algo),
      period,
    });
    return {
      otp,
      remainingMs: this.expiresIn(period),
    };
  }

  private translateHashAlgorithm(format: string = "SHA-1"): string {
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

  private expiresIn(period: number): number {
    const periodMs = period * 1000;
    const epoch = Date.now();
    const elapsed = epoch % periodMs;
    const remaining = periodMs - elapsed;
    return remaining;
  }
}
