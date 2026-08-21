# Local Monitoring and Scheduling

LotusWatch can register public website targets, store scan history in a local
SQLite database, compare consecutive runs, and expose non-interactive commands
for an operating-system scheduler. LotusWatch does not install or run a
background daemon.

## Database Selection

Without `--database`, LotusWatch uses a platform-specific per-user data path.
For scheduled jobs, use an explicit absolute path so the interactive shell and
the scheduler do not accidentally use different databases.

```powershell
lotuswatch monitor list --database C:\LotusWatchData\monitoring.db
```

```bash
lotuswatch monitor list --database /var/lib/lotuswatch/monitoring.db
```

The database and exported reports can contain target URLs, certificate
metadata, HTTP headers, DNS values, diagnostics, and finding evidence. SQLite
storage is not encrypted or authenticated by LotusWatch. Restrict filesystem
permissions, do not place credentials or tokens in target URLs, and review
exported JSON before sharing it.

## Register and Run a Target

Registering a profile does not perform a scan:

```bash
lotuswatch monitor add production example.com --database /absolute/path/monitoring.db
```

Run one stored scan and automatic previous-run comparison:

```bash
lotuswatch monitor run production --database /absolute/path/monitoring.db
```

The first compatible run establishes the baseline. Later runs compare with the
newest earlier compatible run for the same canonical target. A successful
command means the validated run was stored; it does not mean the target has no
findings.

## Optional Notifications

Notifications are disabled by default. Select one or more channels explicitly
and provide a severity threshold for added findings and current snapshots of
changed findings:

```bash
lotuswatch monitor run production --notify webhook --notify-on medium
```

```bash
lotuswatch monitor run production --notify webhook --notify telegram --notify-on high
```

Webhook delivery reads `LOTUSWATCH_WEBHOOK_URL` and the optional
`LOTUSWATCH_WEBHOOK_SECRET`. Telegram delivery reads
`LOTUSWATCH_TELEGRAM_BOT_TOKEN` and `LOTUSWATCH_TELEGRAM_CHAT_ID`. Configure
only the variables required by the selected channels. Do not place their
values in command-line arguments, documentation, scheduler logs, or the
monitoring database.

The initial compatible run establishes a baseline and does not alert by
default. Later runs deliver only when an added finding or the current version
of a changed finding meets `--notify-on`. Resolved and unchanged findings do
not independently trigger delivery. The threshold is an operator-selected
automation policy, not a complete risk score.

Preview the selected event and channels without contacting a provider:

```bash
lotuswatch monitor run production --notify webhook --notify-on medium --notification-dry-run
```

A notification dry run still performs and stores the monitoring scan. It does
not resolve provider secrets or send a webhook or Telegram request.

Notification outcomes are printed after the stored run identifier:

- Exit code `0` means no notification was required, the dry run completed, or
  every attempted delivery succeeded.
- Exit code `2` means command usage, monitoring execution, or storage failed.
- Exit code `3` means the scan was stored but at least one explicitly requested
  notification could not be delivered.

Exit code `3` does not mean the stored scan was lost. Delivery is best effort;
a timeout after provider acceptance can cause a later retry or monitoring run
to produce a duplicate notification. LotusWatch does not provide exactly-once
delivery or a persistent delivery queue.

## Inspect History

List recent runs in newest-first order:

```bash
lotuswatch monitor history production --limit 20 --database /absolute/path/monitoring.db
```

Display a complete stored report in the terminal:

```bash
lotuswatch monitor show RUN_ID --database /absolute/path/monitoring.db
```

Export a stored report without overwriting an existing file:

```bash
lotuswatch monitor show RUN_ID --database /absolute/path/monitoring.db --format json --output stored-report.json
```

History and exported reports are sensitive. Review terminal capture, job logs,
and JSON artifacts before sharing or committing them.

## Retention

Preview the exact run identifiers outside the newest retained set:

```bash
lotuswatch monitor prune production --keep 30 --database /absolute/path/monitoring.db
```

The default is a dry run. After reviewing the listed identifiers, apply the
same policy explicitly:

```bash
lotuswatch monitor prune production --keep 30 --database /absolute/path/monitoring.db --apply
```

Pruning deletes only the identifiers selected by that invocation in one
transaction. It keeps at least one run and preserves the target profile. If the
database changes between previews, review the newly calculated list before
applying it. LotusWatch does not run retention automatically.

## PowerShell Task Scheduler

Use explicit executable and database paths. The following example creates a
daily non-interactive task for a profile named `production`:

```powershell
$action = New-ScheduledTaskAction `
    -Execute "C:\Tools\LotusWatch\.venv\Scripts\lotuswatch.exe" `
    -Argument "monitor run production --database C:\LotusWatchData\monitoring.db"
$trigger = New-ScheduledTaskTrigger -Daily -At "03:00"
Register-ScheduledTask `
    -TaskName "LotusWatch production" `
    -Action $action `
    -Trigger $trigger `
    -Description "Run one LotusWatch monitoring scan"
```

To enable scheduled notifications, configure the required
`LOTUSWATCH_WEBHOOK_URL`, `LOTUSWATCH_WEBHOOK_SECRET`,
`LOTUSWATCH_TELEGRAM_BOT_TOKEN`, or `LOTUSWATCH_TELEGRAM_CHAT_ID` variables in
the protected environment of the task account. Add only non-secret channel
selection to `-Argument`, for example:

```powershell
-Argument "monitor run production --database C:\LotusWatchData\monitoring.db --notify webhook --notify-on high"
```

Do not embed environment variable values in the scheduled-task arguments.

Run the task under an account that can read the installation and read and write
the selected database directory. Configure Task Scheduler history or a
separate protected log if operational output must be retained.

## POSIX cron

Use absolute paths and redirect output to a protected log file:

```cron
0 3 * * * /opt/lotuswatch/.venv/bin/lotuswatch monitor run production --database /var/lib/lotuswatch/monitoring.db >> /var/log/lotuswatch-production.log 2>&1
```

For notification-enabled cron jobs, load the required Telegram or webhook
variables from a protected account environment or wrapper configuration and
keep secret values out of the crontab. The cron command contains only the
channel and threshold:

```cron
0 3 * * * /opt/lotuswatch/.venv/bin/lotuswatch monitor run production --database /var/lib/lotuswatch/monitoring.db --notify telegram --notify-on high >> /var/log/lotuswatch-production.log 2>&1
```

Ensure the cron account owns or can access the database and log paths. Do not
put secrets in the command line, profile target, crontab, or log filename. Use
only a protected account environment or wrapper configuration for provider
credentials.

## Locking and Concurrency

Use one scheduled process per database and avoid overlapping runs. SQLite uses
a bounded busy timeout, but LotusWatch does not provide multi-process write
coordination beyond SQLite locking. Separate profiles can share one database
when their jobs do not overlap.

## Backups

Stop scheduled LotusWatch jobs before copying the database. Back up the
database with filesystem permissions appropriate for sensitive monitoring
history, verify that the backup can be read, and protect or remove retired
copies according to your retention policy. LotusWatch does not create,
encrypt, authenticate, rotate, or restore backups automatically.
