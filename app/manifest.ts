import type { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'Hardware-Enclave & Post-Quantum Crypto PWA',
    short_name: 'CryptoPWA',
    description:
      'High-assurance Next.js PWA with WebCrypto non-extractable ECDSA P-256 and NIST FIPS 204 ML-DSA Post-Quantum signatures.',
    start_url: '/',
    display: 'standalone',
    background_color: '#0a0a0a',
    theme_color: '#0a0a0a',
    icons: [
      {
        src: '/next.svg',
        sizes: '192x192',
        type: 'image/svg+xml',
        purpose: 'any',
      },
      {
        src: '/next.svg',
        sizes: '512x512',
        type: 'image/svg+xml',
        purpose: 'maskable',
      },
    ],
  };
}
