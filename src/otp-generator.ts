import { SecretsFileProvider } from "./secrets-file-provider";
import { decrypt } from "./decrypt";
import totp from "totp-generator";
import { IContent } from "./types";
import { Worker } from "worker_threads";
import path from "path";

export interface ServiceInformation {
  issuer: string;
  label: string;
  thumbnail: string;
}

export interface Otp {
  otp: string;
  remainingMs: number;
}

type WorkerJob = any;

async function runWorkerJob(job: WorkerJob) {
  const worker = new Worker(path.resolve(__dirname, "./otp-generator-v2.js"), {
    workerData: job,
  });
  const p = new Promise((resolve, reject) => {
    worker.addListener("message", resolve);
    worker.addListener("error", reject);
    worker.addListener("messageerror", reject);
  });
  return p;
}

export class OtpGenerator {
  private encryptedBackup: IEncryptedBackup | null = null;

  constructor(private secretsFileProvider: SecretsFileProvider) {}

  async unlock(password: string): Promise<void> {
    this.encryptedBackup = this.secretsFileProvider.getContents();
  }

  lock(): void {
    this.encryptedBackup = null;
  }

  isUnlocked(): boolean {
    return this.encryptedBackup != null;
  }

  listServices(): ServiceInformation[] {
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
