import { SecretsFileProvider } from "./secrets-file-provider";
import { IEncryptedBackup } from "./types";
import { Worker } from "worker_threads";
import path from "path";
import crypto from "crypto";

export interface ServiceInformation {
  issuer: string;
  label: string;
  thumbnail: string;
}

export interface Otp {
  otp: string;
  remainingMs: number;
}

interface IWorkerInit {
  type: "init";
  backup: IEncryptedBackup;
  password: string;
  ephemeralKey: string;
}

interface IWorkerGenOTP {
  type: "genotp";
  issuer: string;
  label: string;
  backup: IEncryptedBackup;
  ephemeralKey: string;
}

interface IWorkerGenOTPResponse extends Otp {
  serviceList: ServiceInformation[];
}

interface IWorkerInitResponse {
  serviceList: ServiceInformation[];
}

export type WorkerJob = IWorkerInit | IWorkerGenOTP;
export type WorkerResponse = IWorkerInitResponse | IWorkerGenOTPResponse;

async function runWorkerJob(job: IWorkerInit): Promise<IWorkerInitResponse>;
async function runWorkerJob(job: IWorkerGenOTP): Promise<IWorkerGenOTPResponse>;
async function runWorkerJob(job: WorkerJob): Promise<WorkerResponse> {
  const worker = new Worker(path.resolve(__dirname, "./otp-generator-v2.js"), {
    workerData: job,
  });
  const p = new Promise<WorkerResponse>((resolve, reject) => {
    worker.addListener("message", resolve);
    worker.addListener("error", reject);
    worker.addListener("messageerror", reject);
  });
  p.finally(() => worker.terminate());
  return p;
}

export class OtpGenerator {
  private encryptedBackup: IEncryptedBackup | null = null;
  private services: ServiceInformation[] = [];
  private ephemeralKey: string | null = null;

  constructor(private secretsFileProvider: SecretsFileProvider) {}

  async unlock(password: string): Promise<void> {
    this.encryptedBackup = this.secretsFileProvider.getContents();
    this.ephemeralKey = crypto.randomBytes(32).toString("hex");
    const { serviceList } = await runWorkerJob({
      type: "init",
      backup: this.encryptedBackup,
      password,
      ephemeralKey: this.ephemeralKey,
    });
    this.services = serviceList;
  }

  lock(): void {
    this.encryptedBackup = null;
  }

  isUnlocked(): boolean {
    return this.encryptedBackup != null;
  }

  listServices(): ServiceInformation[] {
    return this.services;
  }

  async generateOTP(issuer: string, label: string): Promise<Otp> {
    const { serviceList, otp, remainingMs } = await runWorkerJob({
      type: "genotp",
      backup: this.encryptedBackup,
      issuer,
      label,
      ephemeralKey: this.ephemeralKey,
    });
    this.services = serviceList;
    return { otp, remainingMs };
  }
}
