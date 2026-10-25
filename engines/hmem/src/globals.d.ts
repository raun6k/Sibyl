declare module "node:fs" {
  export function writeSync(fd: number, text: string): number;
  export function existsSync(file: string): boolean;
  export function mkdirSync(dir: string, options?: { recursive?: boolean }): void;
  export function readFileSync(file: string, encoding: "utf8"): string;
  export function writeFileSync(file: string, text: string): void;
  export function rmSync(dir: string, options?: { recursive?: boolean; force?: boolean }): void;
}

declare module "node:path" {
  export function join(...parts: string[]): string;
  export function resolve(...parts: string[]): string;
}

declare module "node:readline" {
  interface LineReader {
    on(event: "line", listener: (line: string) => void): void;
  }
  export function createInterface(options: { input: unknown }): LineReader;
}

declare const process: {
  stdin: unknown;
  cwd(): string;
  exit(code?: number): never;
  env: Record<string, string | undefined>;
};
