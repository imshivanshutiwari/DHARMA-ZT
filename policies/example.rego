package dharma.mesh

default allow = false

allow {
    input.src_peer_id == data.peers[_].id
    input.protocol == "tcp"
    input.port == 443
    data.peers[input.src_peer_id].role == "commander"
    input.trust_score >= 0.80
}

allow {
    input.src_peer_id == data.peers[_].id
    input.protocol == "udp"
    input.port == 53
    data.peers[input.src_peer_id].role == "drone"
    input.trust_score >= 0.60
}
