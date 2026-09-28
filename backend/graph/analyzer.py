import networkx as nx
from models.schemas import GraphData, GraphNode, GraphLink, FlowRecord

class GraphAnalyzer:
    def __init__(self):
        self.G = nx.DiGraph()
        
    def add_flow(self, flow: FlowRecord, suspicion_increment: float = 0.0):
        src = flow.src_ip
        dst = flow.dst_ip
        
        # Add or update Source Node
        if not self.G.has_node(src):
            self.G.add_node(src, group=1, suspicion_score=0.0)
        self.G.nodes[src]['suspicion_score'] += suspicion_increment
        
        # Add or update Dest Node
        if not self.G.has_node(dst):
            self.G.add_node(dst, group=2, suspicion_score=0.0)
        
        # Add or update Edge
        if self.G.has_edge(src, dst):
            self.G[src][dst]['weight'] += 1
        else:
            self.G.add_edge(src, dst, weight=1)
            
        self._prune_if_needed()
            
    def _prune_if_needed(self, max_nodes: int = 500):
        if len(self.G) > max_nodes:
            # Remove 50 nodes with lowest suspicion score and degree
            nodes_to_remove = sorted(
                self.G.nodes(data=True), 
                key=lambda x: (x[1].get('suspicion_score', 0), self.G.degree(x[0]))
            )[:50]
            self.G.remove_nodes_from([n[0] for n in nodes_to_remove])
            
    def get_graph_data(self) -> GraphData:
        nodes = []
        for node, data in self.G.nodes(data=True):
            nodes.append(GraphNode(
                id=node,
                group=data.get('group', 1),
                suspicion_score=data.get('suspicion_score', 0.0)
            ))
            
        links = []
        for src, dst, data in self.G.edges(data=True):
            links.append(GraphLink(
                source=src,
                target=dst,
                value=data.get('weight', 1)
            ))
            
        return GraphData(nodes=nodes, links=links)

analyzer = GraphAnalyzer()
