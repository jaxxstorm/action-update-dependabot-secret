import { jest } from "@jest/globals";
import { Octokit } from "@octokit/core";
import { getPublicKey, encryptSecret, updateDependabotSecret } from "./main";
import sodium from "libsodium-wrappers";

// Mock Octokit
jest.mock("@octokit/core");

describe("Dependabot Secret Update Action", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("getPublicKey", () => {
    it("should fetch the public key from GitHub API", async () => {
      const mockRequest = jest.fn<any>().mockResolvedValue({
        data: {
          key_id: "123456789",
          key: "test-public-key-base64",
        },
      });

      const mockOctokit = {
        request: mockRequest,
      } as unknown as Octokit;

      const result = await getPublicKey(mockOctokit, "testowner", "testrepo");

      expect(result).toEqual({
        key_id: "123456789",
        key: "test-public-key-base64",
      });

      expect(mockRequest).toHaveBeenCalledWith(
        "GET /repos/{owner}/{repo}/dependabot/secrets/public-key",
        {
          owner: "testowner",
          repo: "testrepo",
          headers: {
            "X-GitHub-Api-Version": "2022-11-28",
          },
        }
      );
    });

    it("should handle API errors", async () => {
      const mockRequest = jest
        .fn<any>()
        .mockRejectedValue(new Error("API Error: Not Found"));

      const mockOctokit = {
        request: mockRequest,
      } as unknown as Octokit;

      await expect(
        getPublicKey(mockOctokit, "testowner", "testrepo")
      ).rejects.toThrow("API Error: Not Found");
    });
  });

  describe("encryptSecret", () => {
    it("should encrypt a secret value using the public key", async () => {
      await sodium.ready;

      // Generate a test key pair
      const keyPair = sodium.crypto_box_keypair();
      const publicKey = sodium.to_base64(
        keyPair.publicKey,
        sodium.base64_variants.ORIGINAL
      );

      const secretValue = "my-secret-value";
      const encrypted = await encryptSecret(secretValue, publicKey);

      // Verify the result is base64
      expect(encrypted).toMatch(/^[A-Za-z0-9+/]+=*$/);
      expect(encrypted.length).toBeGreaterThan(0);

      // Verify we can decrypt it (to ensure encryption worked correctly)
      const encryptedBytes = sodium.from_base64(
        encrypted,
        sodium.base64_variants.ORIGINAL
      );
      const decrypted = sodium.crypto_box_seal_open(
        encryptedBytes,
        keyPair.publicKey,
        keyPair.privateKey
      );
      const decryptedString = sodium.to_string(decrypted);

      expect(decryptedString).toBe(secretValue);
    });

    it("should produce different encrypted values for the same input", async () => {
      await sodium.ready;

      const keyPair = sodium.crypto_box_keypair();
      const publicKey = sodium.to_base64(
        keyPair.publicKey,
        sodium.base64_variants.ORIGINAL
      );

      const secretValue = "my-secret-value";
      const encrypted1 = await encryptSecret(secretValue, publicKey);
      const encrypted2 = await encryptSecret(secretValue, publicKey);

      // Due to the nature of sealed boxes, each encryption should be different
      expect(encrypted1).not.toBe(encrypted2);
    });
  });

  describe("updateDependabotSecret", () => {
    it("should update the Dependabot secret via GitHub API", async () => {
      const mockRequest = jest.fn<any>().mockResolvedValue({
        status: 204,
        data: {},
      });

      const mockOctokit = {
        request: mockRequest,
      } as unknown as Octokit;

      await updateDependabotSecret(
        mockOctokit,
        "testowner",
        "testrepo",
        "MY_SECRET",
        "encrypted-value-base64",
        "key-id-123"
      );

      expect(mockRequest).toHaveBeenCalledWith(
        "PUT /repos/{owner}/{repo}/dependabot/secrets/{secret_name}",
        {
          owner: "testowner",
          repo: "testrepo",
          secret_name: "MY_SECRET",
          encrypted_value: "encrypted-value-base64",
          key_id: "key-id-123",
          headers: {
            "X-GitHub-Api-Version": "2022-11-28",
          },
        }
      );
    });

    it("should handle API errors when updating secret", async () => {
      const mockRequest = jest
        .fn<any>()
        .mockRejectedValue(new Error("API Error: Unauthorized"));

      const mockOctokit = {
        request: mockRequest,
      } as unknown as Octokit;

      await expect(
        updateDependabotSecret(
          mockOctokit,
          "testowner",
          "testrepo",
          "MY_SECRET",
          "encrypted-value",
          "key-id"
        )
      ).rejects.toThrow("API Error: Unauthorized");
    });
  });

  describe("Integration test", () => {
    it("should complete the full workflow of fetching key, encrypting, and updating", async () => {
      await sodium.ready;

      // Generate a test key pair
      const keyPair = sodium.crypto_box_keypair();
      const publicKeyBase64 = sodium.to_base64(
        keyPair.publicKey,
        sodium.base64_variants.ORIGINAL
      );

      const mockRequest = jest
        .fn<any>()
        // First call: get public key
        .mockResolvedValueOnce({
          data: {
            key_id: "test-key-id-123",
            key: publicKeyBase64,
          },
        })
        // Second call: update secret
        .mockResolvedValueOnce({
          status: 204,
          data: {},
        });

      const mockOctokit = {
        request: mockRequest,
      } as unknown as Octokit;

      // Step 1: Get public key
      const publicKey = await getPublicKey(mockOctokit, "testowner", "testrepo");
      expect(publicKey.key_id).toBe("test-key-id-123");

      // Step 2: Encrypt secret
      const encryptedValue = await encryptSecret("my-secret", publicKey.key);
      expect(encryptedValue).toBeTruthy();

      // Step 3: Update secret
      await updateDependabotSecret(
        mockOctokit,
        "testowner",
        "testrepo",
        "MY_SECRET",
        encryptedValue,
        publicKey.key_id
      );

      // Verify all API calls were made correctly
      expect(mockRequest).toHaveBeenCalledTimes(2);
    });
  });
});
