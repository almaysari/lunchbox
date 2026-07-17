// S3-compatible storage adapter — structural skeleton implementing the same
// Storage Provider Contract as LocalStorage (core/storage.js).
// Activation plan: `npm install @aws-sdk/client-s3 @aws-sdk/s3-request-presigner`,
// set MADAR_STORAGE=s3 plus S3_BUCKET / S3_REGION / S3_ENDPOINT / credentials,
// then fill in the marked calls. Until then every method throws loudly so a
// misconfiguration can never silently store or serve attachments.
class S3Storage {
  constructor({ maxBytes }) {
    this.maxBytes = maxBytes;
    this.bucket = process.env.S3_BUCKET;
    this.region = process.env.S3_REGION;
    this.endpoint = process.env.S3_ENDPOINT; // for MinIO / R2 / other S3-compatible stores
    if (!this.bucket) throw new Error('S3 storage selected but S3_BUCKET is not set');
    throw new Error('S3Storage is a prepared skeleton — install @aws-sdk/client-s3 and complete the marked methods before use.');
  }

  /* eslint-disable no-unused-vars */
  async putObject(buffer) {
    // 1) enforce this.maxBytes  2) key = crypto.randomBytes(24).toString('hex')
    // 3) PutObjectCommand({ Bucket, Key: key, Body: buffer, ServerSideEncryption: 'AES256' })
    // 4) return { key, sha256, size }
    throw new Error('not implemented');
  }
  async getObject(key, range) {
    // GetObjectCommand({ Bucket, Key: key, Range: range && `bytes=${range.start}-${range.end}` }) → Body stream
    throw new Error('not implemented');
  }
  async deleteObject(key) { throw new Error('not implemented'); }
  async exists(key) { throw new Error('not implemented'); }       // HeadObjectCommand
  async metadata(key) { throw new Error('not implemented'); }     // HeadObjectCommand → { size, createdAt }
  async signedUrl(key, ttlSeconds) { throw new Error('not implemented'); } // getSignedUrl(GetObjectCommand)
}

module.exports = { S3Storage };
