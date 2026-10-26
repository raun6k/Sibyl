declare module "node:crypto" {
  interface Hash {
    update(data: string): Hash;
    digest(encoding: "hex"): string;
  }
  export function createHash(algorithm: string): Hash;
}

declare module "node:fs" {
  export function writeSync(fd: number, text: string): number;
}

declare module "node:readline" {
  interface LineReader {
    on(event: "line", listener: (line: string) => void): void;
  }
  export function createInterface(options: { input: unknown }): LineReader;
}

declare const process: {
  stdin: unknown;
  exit(code?: number): never;
  env: Record<string, string | undefined>;
};
