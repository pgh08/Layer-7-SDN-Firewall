from pox.core import core
import pox.openflow.libopenflow_01 as of

# Get a reference to the logger
log = core.getLogger()

# Function to handle switch connection
def _handle_ConnectionUp(event):
    log.debug("Switch %s connected" % (event.connection,))
    # Query the switch for its flow table entries
    msg = of.ofp_stats_request()
    msg.type = of.OFPST_FLOW
    event.connection.send(msg)

# Function to handle flow stats reply
def _handle_FlowStatsReply(event):
    for stat in event.stats:
        log.debug("Flow entry: %s" % (stat,))

# Function to launch the module
def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("FlowStatsReceived", _handle_FlowStatsReply)
    log.debug("Flow rule checker running.")