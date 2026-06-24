import { Command }              from 'commander';
import * as readline             from 'readline';
import { requireAuth }           from '../auth';
import { streamAsk }             from '../llm';
import { getAllFindings }         from '../../lib/findings-store';
import type { LiveFinding, DiscoveredHost } from '../../lib/engine/types';

type ConvMessage = { role: 'user' | 'assistant'; content: string };

async function runInteractive(
  findings:  LiveFinding[],
  hosts:     DiscoveredHost[],
  history:   ConvMessage[],
): Promise<void> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  process.stdout.write('\x1b[1;36mADVERSA AI\x1b[0m  \x1b[2mType a question. Ctrl+C to exit.\x1b[0m\n\n');

  const ask = (): void => {
    rl.question('\x1b[36m>\x1b[0m ', async (input) => {
      const q = input.trim();
      if (!q) { ask(); return; }
      if (q === '/exit' || q === '/quit') { rl.close(); return; }
      if (q === '/clear') { history.length = 0; process.stdout.write('\x1b[2mContext cleared.\x1b[0m\n\n'); ask(); return; }
      if (q === '/findings') {
        process.stdout.write(`${findings.length} findings loaded.\n`);
        findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 5).forEach(f => {
          process.stdout.write(`  [${f.severity}] ${f.host} — ${f.title}\n`);
        });
        process.stdout.write('\n');
        ask();
        return;
      }

      process.stdout.write('\x1b[36mAI\x1b[0m  ');
      let assistantMsg = '';

      await streamAsk(
        q,
        findings,
        hosts,
        (chunk) => {
          process.stdout.write(chunk);
          assistantMsg += chunk;
        },
        history,
      );

      process.stdout.write('\n\n');
      history.push({ role: 'user', content: q });
      history.push({ role: 'assistant', content: assistantMsg });

      ask();
    });
  };

  ask();
}

export function buildAskCommand(): Command {
  return new Command('ask')
    .description('Chat with the AI about current findings (interactive or one-shot)')
    .argument('[question...]', 'Question to ask (omit for interactive mode)')
    .option('--engagement <id>', 'Filter findings by engagement ID')
    .action(async (questionParts: string[], opts: { engagement?: string }) => {
      requireAuth();

      const allFindings = getAllFindings();
      const findings = opts.engagement
        ? allFindings.filter(f => f.engagementId === opts.engagement)
        : allFindings;

      const hosts: DiscoveredHost[] = [...new Map(
        findings.map(f => [f.host, { ip: f.host, ports: f.port ? [f.port] : [], services: [] }])
      ).values()];

      const question = questionParts.join(' ').trim();
      const history: ConvMessage[] = [];

      if (!question) {
        // Interactive mode
        await runInteractive(findings, hosts, history);
        return;
      }

      // One-shot mode
      process.stdout.write('\x1b[36mAI\x1b[0m  ');
      await streamAsk(question, findings, hosts, (chunk) => process.stdout.write(chunk));
      process.stdout.write('\n');
    });
}
