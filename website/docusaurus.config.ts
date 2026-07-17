import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'tenant-tail',
  tagline: 'Independently verify governance certificates and claim provenance, offline, with no trust in the producer.',
  favicon: 'img/favicon.ico',

  // GitHub Pages deployment config
  url: 'https://statecrafting.github.io',
  baseUrl: '/tenant-tail/',
  // For a custom domain later: set baseUrl: '/' and add static/CNAME.
  organizationName: 'statecrafting',
  projectName: 'tenant-tail',

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    mermaid: true,
  },

  themes: ['@docusaurus/theme-mermaid'],

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl:
            'https://github.com/statecrafting/tenant-tail/tree/main/website/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    navbar: {
      title: 'tenant-tail',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          href: 'https://github.com/statecrafting/tenant-tail',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/getting-started',
            },
            {
              label: 'Concepts',
              to: '/docs/concepts',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/statecrafting/tenant-tail',
            },
          ],
        },
      ],
      copyright: `Copyright ${new Date().getFullYear()} Bartek Kus. Apache-2.0 License.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'json', 'rust', 'toml'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
