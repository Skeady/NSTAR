import click
import logging
import nstar_monitor
import time

logging.getLogger(__name__)
formatter = '%(asctime)s [%(levelname)s] [%(threadName)s] [%(name)s] %(message)s'


@click.command()
@click.option(
    '-a',
    '--audit',
    is_flag=True,
    help='run audit on network'
)
@click.option(
    '-m',
    '--monitor',
    is_flag=True,
    help='monitor network for vulnerabilities'
)
@click.option(
    '-v',
    '--verbose',
    is_flag=True,
    help='Enable Debugging'
)

# Cli used to handle Args passed by user and setup logging
def cli(audit, monitor, verbose):
    logging.basicConfig(filename='nstar_remediation_logs.log',
                        format=formatter,
                        level=(logging.DEBUG if verbose else logging.INFO))
    logging.info("Starting {}".format('audit' if audit else 'monitoring'))
    if audit:
        nstar_monitor.monitor_devices()
    elif monitor:
        while True:
            nstar_monitor.monitor_devices()
            time.sleep(5)
    else:
        logging.error(
            'Please select to audit or monitor the network, e.g. nstar-remidiation --audit'
        )
    return