import { Cell, NoticeLine, PageHeader, Panel, Row, Table, When } from '../../components/admin.tsx';
import { Button, Tag } from '../../components/ui.tsx';
import { useResource } from '../../lib/console.tsx';
import { AdminPage, type Console } from './AdminPage.tsx';

type Key = {
  kid: string;
  alg: string;
  state: 'staged' | 'active' | 'retiring' | 'retired';
  createdAt: string;
  activatedAt: string | null;
  retireAfter: string | null;
};
type Keys = {
  keys: Key[];
  policy: { stageHours: number; rotationDays: number; retireAfterSeconds: number };
};

const STATE: Record<Key['state'], { label: string; tone: 'success' | 'info' | 'neutral' }> = {
  staged: { label: 'Published, waiting', tone: 'info' },
  active: { label: 'Signing', tone: 'success' },
  retiring: { label: 'Still published', tone: 'neutral' },
  retired: { label: 'Retired', tone: 'neutral' },
};

export function AdminKeys() {
  return <AdminPage crumbs={[['Signing keys']]}>{(c) => <KeysBody c={c} />}</AdminPage>;
}

function KeysBody({ c }: { c: Console }) {
  const { data, reload } = useResource<Keys>('/api/admin/keys');
  const staged = data?.keys.some((k) => k.state === 'staged');
  return (
    <>
      <PageHeader
        eyebrow="ID token signatures"
        title="Signing keys"
        subtitle="Rotating never signs anyone out: a new key is published before it signs, and the old one stays published until its tokens expire."
        action={
          <Button
            variant="primary"
            size="md"
            busy={c.busy === 'rotate'}
            onClick={async () => {
              if (
                await c.act(
                  'rotate',
                  () => c.write('/api/admin/keys/rotate'),
                  'New key published. Apps will pick it up; it starts signing after the waiting period, or when you switch.',
                )
              )
                void reload();
            }}
          >
            Rotate key
          </Button>
        }
      />
      <NoticeLine notice={c.notice} />
      {data && (
        <p className="mt-4 font-mono text-mono-sm text-fg-subtle">
          automatic rotation{' '}
          {data.policy.rotationDays ? `every ${data.policy.rotationDays} days` : 'off'} · new keys
          wait {data.policy.stageHours}h · old keys stay published{' '}
          {Math.round(data.policy.retireAfterSeconds / 60)} min
        </p>
      )}
      <Panel
        label="Keys"
        action={
          staged && (
            <Button
              size="md"
              variant="secondary"
              busy={c.busy === 'promote'}
              onClick={async () => {
                if (
                  await c.act(
                    'promote',
                    () => c.write('/api/admin/keys/promote'),
                    'Switched. The new key signs from now on.',
                  )
                )
                  void reload();
              }}
            >
              Start signing with the new key now
            </Button>
          )
        }
      >
        <Table
          head={['Key ID', 'Algorithm', 'State', 'Created', 'Signing since', 'Unpublished after']}
        >
          {[...(data?.keys ?? [])].reverse().map((k) => (
            <Row key={k.kid}>
              <Cell mono>{k.kid.slice(0, 16)}…</Cell>
              <Cell mono>{k.alg}</Cell>
              <Cell>
                <Tag tone={STATE[k.state].tone}>{STATE[k.state].label}</Tag>
              </Cell>
              <Cell muted>
                <When iso={k.createdAt} />
              </Cell>
              <Cell muted>{k.activatedAt ? <When iso={k.activatedAt} /> : '—'}</Cell>
              <Cell muted>{k.retireAfter ? <When iso={k.retireAfter} /> : '—'}</Cell>
            </Row>
          ))}
        </Table>
      </Panel>
    </>
  );
}
