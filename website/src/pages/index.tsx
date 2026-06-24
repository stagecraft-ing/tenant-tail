import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import styles from './index.module.css';

function HomepageHero() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={styles.heroBanner}>
      <div className="container">
        <h1 className={styles.heroTitle}>tenant-tail</h1>
        <p className={styles.heroSubtitle}>{siteConfig.tagline}</p>
        <div className={styles.installLine}>
          <code>npm i -D tenant-tail</code>
        </div>
        <div className={styles.buttons}>
          <Link
            className="button button--primary button--lg"
            to="/docs/getting-started">
            Get Started
          </Link>
        </div>
      </div>
    </header>
  );
}

interface FeatureItem {
  title: string;
  description: string;
}

const featureList: FeatureItem[] = [
  {
    title: 'Offline and identity-free',
    description:
      'Makes no network calls. A JWKS is a saved file. Holds no signing keys and never contacts an identity provider.',
  },
  {
    title: 'Read-only, never writes the audited project',
    description:
      'The provenance report goes to stdout. The verifier never mutates the project it checks, down to the package boundary.',
  },
  {
    title: 'Tamper-evident, catches a single changed byte',
    description:
      'Re-derives artifact hashes and replays the manifest chain. A single changed byte surfaces as a distinct verification failure.',
  },
];

function Feature({title, description}: FeatureItem) {
  return (
    <div className={styles.featureCard}>
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}

export default function Home(): React.JSX.Element {
  return (
    <Layout
      title="Home"
      description="Independently verify governance certificates and claim provenance, offline, with no trust in the producer.">
      <HomepageHero />
      <main>
        <section className={styles.features}>
          <div className="container">
            <div className={styles.featureGrid}>
              {featureList.map((props, idx) => (
                <Feature key={idx} {...props} />
              ))}
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
