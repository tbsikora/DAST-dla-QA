import type { Endpoint } from "./sqlInjection";

export type AuthTest = {
  id: string;
  kind: "auth";
  method: string;
  path: string;
};

export function generateAuthTests(_endpoints: Endpoint[]): AuthTest[] {
  return [];
}
