import type {Metadata} from 'next';
import './globals.css'; // Global styles

export const metadata: Metadata = {
  title: 'Advanced Backend Development Skill',
  description: 'Comprehensive, zero-loss backend engineering skill specification covering security, field logic, ID/OTP/token generation, polyglot databases, APIs, payments, resilience, observability, async queues, file upload defense, malware scanning, testing, and DevOps.',
  openGraph: {
    title: 'Advanced Backend Development Skill',
    description: 'Comprehensive, zero-loss backend engineering skill specification covering security, field logic, ID/OTP/token generation, polyglot databases, APIs, payments, resilience, observability, async queues, file upload defense, malware scanning, testing, and DevOps.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Advanced Backend Development Skill',
    description: 'Comprehensive, zero-loss backend engineering skill specification covering security, field logic, ID/OTP/token generation, polyglot databases, APIs, payments, resilience, observability, async queues, file upload defense, malware scanning, testing, and DevOps.',
  },
};

export default function RootLayout({children}: {children: React.ReactNode}) {
  return (
    <html lang="en">
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
