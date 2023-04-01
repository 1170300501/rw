import math
import time
import os
import networkx as nx


def gen_block_scores(file_name):
    blocks_score = {i: math.log(taints_count[k] + math.e) for i, k in enumerate(taints_count.keys())}
    # steady = False
    print(len(edges))

    graph = nx.DiGraph()
    graph.add_nodes_from(nodes_map.keys())
    graph.add_edges_from(edges)
    graph = graph.reverse()

    nodes_katz = nx.katz_centrality(graph, alpha=0.5, beta=blocks_score, max_iter=1000)

    # while not steady:
    #     steady = True
    #     for b in blocks_children.keys():
    #         score = 0.0
    #         for child in blocks_children[b]:
    #             score += 0.5 * blocks_score[child]
    #
    #         score += math.log(taints_count[b] + math.e)
    #         if blocks_score[b] != score:
    #             steady = False
    #
    #         blocks_score[b] = score

    with open(file_name, "w") as f:
        write_ptrs = list()

        for i, tk in nodes_katz.items():
            write_ptrs.append(list(taints_count.keys())[i] + " {:.4f}".format(tk))

        f.write("\n".join(write_ptrs))


if __name__ == '__main__':
    taints_count = dict()
    blocks_children = dict()
    covered_tuples = list()

    with open("taint_count", "r") as f:
        lines = f.readlines()

        for line in lines:
            ptrs = line.strip().split()
            if len(ptrs) == 1:
                continue

            taints_count[ptrs[0]] = int(ptrs[1])

    with open("blocks_children", "r") as f:
        lines = f.readlines()

        for line in lines:
            ptrs = line.strip().split()
            blocks_children[ptrs[0]] = [ptr for ptr in ptrs[1:]]

    nodes_map = {i: int(k) for i, k in enumerate(taints_count.keys())}
    idxs_map = dict(zip(nodes_map.values(), nodes_map.keys()))

    edges = list()
    for block, children in blocks_children.items():
        for child in children:
            edges.append((idxs_map[int(block)], idxs_map[int(child)]))

    gen_block_scores("blocks_score")

    while True:
        time.sleep(5)
        signal = None
        if not os.path.exists("signal"):
            continue
        with open("signal", "r") as f:
            signal = f.read()
        if signal == "1\n":
            covered_tuples.clear()
            with open("cur_coverage", "r") as f:
                covered_tuples = [ele for ele in f.read().split() if ele != '']

            new_edges = list()
            for edge in edges:
                print(nodes_map[edge[0]], nodes_map[edge[1]], (nodes_map[edge[0]] >> 1) ^ nodes_map[edge[1]])
                if str((nodes_map[edge[0]] >> 1) ^ nodes_map[edge[1]]) in covered_tuples:
                    continue

                new_edges.append(edge)

            edges = new_edges

            gen_block_scores("dyn_blocks_score")

            with open("signal", "w") as f:
                f.write("0\n")

            print("covered " + str(len(covered_tuples)) + " edges, generate new graph.")
