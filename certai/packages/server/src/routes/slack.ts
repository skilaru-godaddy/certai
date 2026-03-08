import { App as SlackApp } from '@slack/bolt';
import type { FastifyInstance } from 'fastify';
import { createJob, startAnalysis, getJob, JobStatus } from '../lib/analyzer.js';
import { parseRepoUrl } from '../lib/github.js';

const SLACK_PORT = Number(process.env.SLACK_PORT ?? 3002);
const WEB_BASE_URL = process.env.WEB_BASE_URL ?? 'http://localhost:5173';

export async function registerSlack(_app: FastifyInstance) {
  const slackApp = new SlackApp({
    token: process.env.SLACK_BOT_TOKEN!,
    signingSecret: process.env.SLACK_SIGNING_SECRET!,
  });

  slackApp.command('/certai', async ({ command, ack, respond, client }) => {
    await ack();

    const repoUrl = command.text.trim();
    if (!repoUrl) {
      await respond('Usage: `/certai github.secureserver.net/org/repo`');
      return;
    }

    // Validate URL
    try {
      parseRepoUrl(repoUrl);
    } catch {
      await respond(`❌ Invalid repo URL: \`${repoUrl}\``);
      return;
    }

    // Acknowledge in channel (ephemeral)
    await respond({
      response_type: 'ephemeral',
      text: `⚙️ Analyzing \`${repoUrl.split('/').pop()}\`... I'll DM you when ready (~45s)`,
    });

    // Start analysis job
    const job = createJob(repoUrl);
    startAnalysis(job.id);

    // Poll until done, then DM user
    const userId = command.user_id;
    const pollInterval = setInterval(async () => {
      const j = getJob(job.id);
      if (!j) { clearInterval(pollInterval); return; }

      if (j.status === JobStatus.Done && j.result) {
        clearInterval(pollInterval);
        const r = j.result;
        const viewerUrl = `${WEB_BASE_URL}?jobId=${job.id}`;

        await client.chat.postMessage({
          channel: userId,
          text: `✅ CertAI — ${repoUrl.split('/').pop()}`,
          blocks: [
            {
              type: 'section',
              text: {
                type: 'mrkdwn',
                text: `✅ *CertAI complete*\n\n*Repo:* \`${repoUrl}\`\n*Risk Category:* \`${r.riskCategory}\`\n*Threats found:* ${r.threats.length}\n*Questionnaire:* ${r.questionnaire.length}/29 answered`,
              },
            },
            {
              type: 'actions',
              elements: [
                {
                  type: 'button',
                  text: { type: 'plain_text', text: '📄 View Full Report' },
                  url: viewerUrl,
                  style: 'primary',
                },
              ],
            },
          ],
        });
      } else if (j.status === JobStatus.Error) {
        clearInterval(pollInterval);
        await client.chat.postMessage({
          channel: userId,
          text: `❌ CertAI failed for \`${repoUrl}\`: ${j.error}`,
        });
      }
    }, 3000);

    // Safety timeout: 5 minutes
    setTimeout(() => clearInterval(pollInterval), 5 * 60 * 1000);
  });

  // Bolt runs its own HTTP server on SLACK_PORT (3002)
  // Point ngrok at port 3002: `ngrok http 3002`
  // Set Slack slash command Request URL to: https://<ngrok-url>/slack/events
  await slackApp.start(SLACK_PORT);
  console.log(`Slack handler running on http://localhost:${SLACK_PORT}/slack/events`);
}
