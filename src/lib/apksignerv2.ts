/**
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { validateDName, DName, validateInput } from './DName';
import { KeyGenerationError, KeyReadingError, ZipError } from './Errors';
import { Zip } from './Zip';
import {uint64ToBytes, writeUint32LE, readUint32LE, uint32ToBytes, concatenateArrays} from './util';
import { asn1, pkcs12, pki, md, util } from 'node-forge';
import { Buffer } from 'buffer';


interface ApkSections {
  contents: Uint8Array;
  centralDirectory: Uint8Array;
  eocd: Uint8Array;
  centralDirectoryOffset: number;
}

export class ApkSignerV2 {
    // APK Signing Block magic number
  private static readonly APK_SIG_BLOCK_MAGIC = new TextEncoder().encode('APK Sig Block 42');
  private static readonly APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;
  #password: string;
  #alias: string;
  #base64DerKey?: string;
  version: string;

  constructor(password: string, readonly alias: string = 'android') {
    validateInput(password, 6, 0);
    this.#password = password;
    if (alias.trim() == '') {
      this.#password = 'android';
    }
    this.#alias = alias;
    this.version = "0.1.0";
  }

  async generateKey(dname: DName): Promise<string> {
    validateDName(dname);
    // Async import
    const { generateX509 } = await import('./keytool');

    this.#base64DerKey = await generateX509(dname, this.#password, this.#alias);
    if (!this.#base64DerKey) {
      throw new KeyGenerationError('Key failed to generate.');
    }
    // Return key here to users can save to device
    return this.#base64DerKey;
  }

  async signPackageV2(zipBlob: File,
                      base64DerKey: string | undefined = undefined,
                      creator: string = 'Web signer'
  ) : Promise<string> {

    let key = base64DerKey || this.#base64DerKey;
    if(!key) {
      throw new KeyReadingError("no base64 der encoder keystore found");
    }

    key = key.split('base64,')[1];

    const zip = await Zip.loadAsync(zipBlob);

    if (zip.isPreviouslySigned()) {
      throw new ZipError('Package was previously signed. Will not sign new package');
    }

    const alignedApkBytes = await this.generateAlignedUnsignedApk(zip);

    const apkSections = this.parseApkSections(alignedApkBytes);

    const p12der = util.decode64(key);
    const signingBlock = await this.generateApkSigningBlock(
      apkSections,
      p12der,
      this.#password,
      this.#alias
    );

    const singedApkBytes = this.insertSigningBlock(alignedApkBytes, signingBlock, apkSections);

    const b64output = this.arrayBufferToBase64(singedApkBytes);
    // Even if it is stripped afterwards most of the times, it's better to
    // continue to append the file specification to be coherent with the v1
    // implementation.
    return 'data:application/zip;base64,' + b64output;
  }

 private async generateAlignedUnsignedApk(zip: Zip): Promise<Uint8Array> {
    const preZipAlign = await zip.generateAsync({
      type: 'arraybuffer',
      compression: 'STORE',
    });

    // Align before signing
    const alignedBlob = await zip.alignZip(preZipAlign);
    const alignedBuffer = await alignedBlob.arrayBuffer();
    return new Uint8Array(alignedBuffer);
  }

  /**
   * Parse APK into its main sections for V2 signing
   */
  private parseApkSections(apkBytes: Uint8Array): ApkSections {
    // Find End of Central Directory (EOCD)
    const eocdOffset = this.findEocdOffset(apkBytes);
    if (eocdOffset === -1) {
      throw new Error('Could not find End of Central Directory');
    }

    // Parse EOCD to get Central Directory info
    const eocd = apkBytes.slice(eocdOffset);
    const centralDirOffset = readUint32LE(eocd, 16); // Offset 16 in EOCD
    const centralDirSize = readUint32LE(eocd, 12);   // Offset 12 in EOCD

    return {
      contents: apkBytes.slice(0, centralDirOffset),
      centralDirectory: apkBytes.slice(centralDirOffset, centralDirOffset + centralDirSize),
      eocd: eocd,
      centralDirectoryOffset: centralDirOffset
    };
  }

   /**
   * Find End of Central Directory offset by searching backwards for
   * signature
   */
  private findEocdOffset(apkBytes: Uint8Array): number {
    // EOCD signature: 0x06054b50 (little endian: 50 4b 05 06)
    const signature = new Uint8Array([0x50, 0x4b, 0x05, 0x06]);

    // Search backwards from end of file
    for (let i = apkBytes.length - 4; i >= 0; i--) {
      if (apkBytes[i] === signature[0] &&
          apkBytes[i + 1] === signature[1] &&
          apkBytes[i + 2] === signature[2] &&
          apkBytes[i + 3] === signature[3]) {
        return i;
      }
    }
    return -1;
  }

  /**
   * Generate the APK Signing Block for V2
   */
  private async generateApkSigningBlock(
    sections: ApkSections,
    p12der: string,
    password: string,
    alias: string
  ): Promise<Uint8Array> {
    // Create signed data structure
    const signedData = await this.createSignedData(sections, p12der, password, alias);

    // Build the signing block
    const v2Block = this.buildV2SignatureBlock(signedData);

    return this.buildApkSigningBlock([{
      id: ApkSignerV2.APK_SIGNATURE_SCHEME_V2_BLOCK_ID,
      value: v2Block
    }]);
  }

  /**
   * Create the signed data structure for V2
   * This is a simplified version - it supports only RSA signing
   */
  private async createSignedData(
    apkSections: ApkSections,
    p12der: string,
    password: string,
    alias: string
  ): Promise<Uint8Array> {

    // The signed data contains:
    // - Algorithm ID (RSA with SHA-256)
    // - Digests of the three sections
    // - Public key
    // - Additional attributes

    // generate Cert
    // Parse P12 keystore
    const asn1Cert = asn1.fromDer(p12der);
    const p12 = pkcs12.pkcs12FromAsn1(asn1Cert, password);

    // Get certificate
    let bag = p12.getBags({ friendlyName: alias, bagType: pki.oids.certBag });
    const cert = this.getCert(bag.friendlyName);

    // Convert certificate object to DER bytes
    const certificateDer = asn1.toDer(pki.certificateToAsn1(cert)).getBytes();

    // Get certificate bytes
    const certificateBytes = new Uint8Array(certificateDer.split('').map(c => c.charCodeAt(0)));
    // console.log(this.toHex(certificateBytes));

    // Get private key
    bag = p12.getBags({ friendlyName: alias, bagType: pki.oids.pkcs8ShroudedKeyBag });
    const privateKey = this.getKey(bag.friendlyName) as pki.rsa.PrivateKey;

    // Create the data to be signed (this needs to follow V2 format)
    const dataToSign = await this.buildDigestPayload(apkSections, certificateBytes);
    // Sign with your existing signing logic (adapt for V2 format)
    const signature = await this.signDataV2(dataToSign, privateKey, cert);

    // Build the complete signed data structure
    return this.buildCompleteSignedData(dataToSign, signature);
  }

  /**
   * Build the signed data payload according to V2 spec
   */
  private async buildDigestPayload(apkSections: ApkSections, cert: Uint8Array): Promise<Uint8Array> {
    // V2 signed data format:
    // https://source.android.com/security/apksigning/v2
    // Moved length prefix, certificate and additional section encoding to
    // buildSignaturesSection, maybe will restore here?
    const chunks: Uint8Array[] = [];

    // Digests section (length-prefixed list of algorithm ID + digest pairs)
    // Already includes its length prefixed!
    const merkleDigest = await this.calculateMerkleTreeDigest(apkSections);
    const digestEntry = concatenateArrays([
      uint32ToBytes(0x0103), // RSA-PKCS1-v1.5 with SHA-256
      uint32ToBytes(merkleDigest.length),
      merkleDigest
    ]);
    chunks.push(uint32ToBytes( 4 + digestEntry.length));
    chunks.push(uint32ToBytes(digestEntry.length)); // Length prefix
    chunks.push(digestEntry);

    const certificatesSection = this.buildCertificatesSection(cert);
    chunks.push(uint32ToBytes(certificatesSection.length)); // Length prefix
    chunks.push(certificatesSection);

    // 3. Additional attributes (4 bytes)
    chunks.push(uint32ToBytes(0));

    const result = concatenateArrays(chunks);
    // console.log('Signed data payload breakdown: digests(' + digestEntry.length + ') + certs(' + certificatesSection.length + ') + attrs(4) = ' + result.length);

    return result;
  }

  /**
   * Calculate Merkle tree digest according to V2 specification
   * Each section is chunked into 1MB pieces, then tree-hashed
   */
  private async calculateMerkleTreeDigest(apkSections: ApkSections):
    Promise<Uint8Array> {

    // Implementation of APK digest according to the Android APK Signature
    // V2 documentation:
    // https://source.android.com/docs/security/features/apksigning/v2#integrity-protected-contents
    // At this point of program we are building the signature section, but
    // luckily it's the only section that is not integrity protected.
    // After the signing section is completed, which corresponds to the
    // return of generateApkSigningBlock, insertSigningBlock will update
    // the offset of the ZIP Central Directory inside the EOCD section.
    // Now we will compute the checksum of the EOCD section BEFORE this
    // substitution happens, but by definition when checking the signature
    // of an APK, the opposite of insertSigningBlock is performed, so we
    // don't have to mind this potential issue here.

    // Chunked section read
    const CHUNK_SIZE = 1024 * 1024;
    const chunkDigests: Uint8Array[] = [];

    const sections = ['contents', 'centralDirectory', 'eocd'];

    for (const sectionName of sections) {
      const sectionData: Uint8Array = (apkSections as any)[sectionName];
      if (!sectionData) {
        throw new Error(`Missing section: ${sectionName}`);
      }

      for (let offset = 0; offset < sectionData.length; offset += CHUNK_SIZE) {
        const chunkSize = Math.min(CHUNK_SIZE, sectionData.length - offset);
        const chunkData = sectionData.slice(offset, offset + chunkSize);

        // Chunk Digest: 0xa5 + chunk length + chunkData
        const formattedChunk = concatenateArrays([
          new Uint8Array([0xa5]),
          uint32ToBytes(chunkSize),
          chunkData
        ]);

        const chunkHash = await this.sha256Async(formattedChunk);
        chunkDigests.push(chunkHash);
      }
    }


    // The APK V2 final digest is computed as:
    // SHA-256(0x5a || num_chunks || concatenated_chunk_digests)
    const finalData = concatenateArrays([
      new Uint8Array([0x5a]),
      uint32ToBytes(chunkDigests.length),
      concatenateArrays(chunkDigests)
    ]);

    return await this.sha256Async(finalData);
  }


  /**
   * Create raw RSA signature for V2 (different from V1 PKCS#7)
   */
  private async signDataV2(
    dataToSign: Uint8Array,
    privateKey: pki.rsa.PrivateKey,
    cert: any
  ): Promise<{ signature: Uint8Array; publicKey: Uint8Array; certificate: Uint8Array }> {

    // Create hash of data to sign
    const messageDigest = md.sha256.create();
    messageDigest.update(util.binary.raw.encode(dataToSign));

    // Create raw RSA signature (not PKCS#7)
    const signature = privateKey.sign(messageDigest, 'RSASSA-PKCS1-V1_5');
    // console.log("Digested buf: ", messageDigest.digest());
    // const hashHex = messageDigest.digest().toHex();
    // console.log("Hash being signed: ", hashHex);

    // Get public key and certificate in DER format
    const publicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e);
    const publicKeyDer = asn1.toDer(pki.publicKeyToAsn1(publicKey)).getBytes();
    const certificateDer = asn1.toDer(pki.certificateToAsn1(cert)).getBytes();

    return {
      signature: new Uint8Array(signature.split('').map(c => c.charCodeAt(0))),
      publicKey: new Uint8Array(publicKeyDer.split('').map(c => c.charCodeAt(0))),
      certificate: new Uint8Array(certificateDer.split('').map(c => c.charCodeAt(0)))
    };
  }

  /**
   * Insert the signing block into the APK
   */
  private insertSigningBlock(
    apkBytes: Uint8Array,
    signingBlock: Uint8Array,
    sections: ApkSections
  ): Uint8Array {
    const newCentralDirOffset = sections.contents.length + signingBlock.length;

    // Update EOCD with new Central Directory offset
    const updatedEocd = new Uint8Array(sections.eocd);
    writeUint32LE(updatedEocd, 16, newCentralDirOffset);

    // Assemble the new APK
    return concatenateArrays([
      sections.contents,      // Original contents
      signingBlock,          // New signing block
      sections.centralDirectory, // Central Directory
      updatedEocd           // Updated EOCD
    ]);
  }

  /**
   * Build the complete APK Signing Block structure
   */
  private buildApkSigningBlock(pairs: { id: number; value: Uint8Array }[]): Uint8Array {
    const chunks: Uint8Array[] = [];

    // Calculate total size
    let pairsSize = 0;
    for (const pair of pairs) {
      pairsSize += 8 + 4 + pair.value.length; // 8 bytes (length) + 4 bytes (ID) + value
    }

    // Total block size = 8 bytes (size) + pairs + 8 bytes (size again) + 16 bytes (magic)
    const totalBlockSize = 8 + pairsSize + 8 + 16;

    // The size field excludes the first 8 bytes (the size field itself)
    const sizeFieldValue = totalBlockSize - 8;

    // Size of block (8 bytes, little endian) - FIRST occurrence
    chunks.push(uint64ToBytes(sizeFieldValue));

    // Pairs
    for (const pair of pairs) {
      const pairLength = 4 + pair.value.length; // 4 bytes (ID) + value
      chunks.push(uint64ToBytes(pairLength));
      chunks.push(uint32ToBytes(pair.id));
      chunks.push(pair.value);
    }

    // Size of block again (8 bytes) - SECOND occurrence (must match first!)
    chunks.push(uint64ToBytes(sizeFieldValue));

    // Magic number
    chunks.push(ApkSignerV2.APK_SIG_BLOCK_MAGIC);

    return concatenateArrays(chunks);
  }


  /**
   * Build the V2 signature block (contains all signers)
   */
  private buildV2SignatureBlock(signerBlock: Uint8Array): Uint8Array {
    const chunks: Uint8Array[] = [];

    // Number of signers (we have 1)
    // chunks.push(uint32ToBytes(1));
    // Total signer length
    chunks.push(uint32ToBytes(signerBlock.length + 4));

    // Length-prefixed signer block
    chunks.push(uint32ToBytes(signerBlock.length));
    // Signer block
    chunks.push(signerBlock);

    return concatenateArrays(chunks);
  }


  private buildCompleteSignedData(payload: Uint8Array,
           signatureData: { signature: Uint8Array; publicKey: Uint8Array; certificate: Uint8Array } ): Uint8Array {
    const chunks: Uint8Array[] = [];

    // V2 Signer format:
    // - length-prefixed signatures
    // - length-prefixed public key
    // - length-prefixed signed data

    // 1. Signed Data section, encodes:
    // Digest + Certificate + Additional Section
    chunks.push(uint32ToBytes(payload.length));
    chunks.push(payload);

    const signatureSection = this.encodeSignature(signatureData.signature);
    chunks.push(signatureSection);

    // 2. Public key
    chunks.push(uint32ToBytes(signatureData.publicKey.length));
    chunks.push(signatureData.publicKey);

    const result = concatenateArrays(chunks);
    return result;
  }

  private arrayBufferToBase64(buffer: Uint8Array): string {
    return Buffer.from(buffer).toString('base64');
  }

  private buildCertificatesSection(certificate: Uint8Array): Uint8Array {
    const chunks: Uint8Array[] = [];

    // Certificate length and data
    chunks.push(uint32ToBytes(certificate.length));
    chunks.push(certificate);

    return concatenateArrays(chunks);
  }

  private encodeSignature(signature: Uint8Array): Uint8Array {
    const chunks: Uint8Array[] = [];

    // Build the signature struct: algo_id + sig_length + signature_data
    const signatureStruct = concatenateArrays([
      uint32ToBytes(0x0103), // Algorithm ID
      uint32ToBytes(signature.length), // Signature length
      signature // Signature data
    ]);

    // Total signatures length = struct_length_field(4) + signature_struct
    const totalSignaturesLength = 4 + signatureStruct.length;

    // console.log("Total signature length: ", totalSignaturesLength);
    chunks.push(uint32ToBytes(totalSignaturesLength)); // Total length
    // console.log("Signature struct length: ", signatureStruct.length);
    chunks.push(uint32ToBytes(signatureStruct.length)); // Struct length

    chunks.push(signatureStruct); // The actual struct

    return concatenateArrays(chunks);
  }

  // Helper methods for certificate/key extraction
  private getCert(bag: any): any {
    if (bag && bag.length > 0) {
      return bag[0].cert;
    }
    throw new Error('Certificate not found in keystore');
  }

  private getKey(bag: any): any {
    if (bag && bag.length > 0) {
      return bag[0].key;
    }
    throw new Error('Private key not found in keystore');
  }

  // Async SHA-256 for initial digest calculation
  private async sha256Async(data: Uint8Array): Promise<Uint8Array> {
    const bufData = Buffer.from(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', bufData);
    return new Uint8Array(hashBuffer);
  }

  // Debug utility, can be purged in a later release.
  private toHex(buffer: Uint8Array) {
    return Array.prototype.map.call(buffer, x => x.toString(16).padStart(2, '0')).join('');
}
}
