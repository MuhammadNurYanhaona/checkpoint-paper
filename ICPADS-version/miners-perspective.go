func votingRound(currC, currVCert, round) {
	knownCandidates = {}
	// if peer's selected candidate is not eliminated in the last round
	// then starts the new round with the selected candidate 
	if (currC != nil) knownCandidates = {currC.candidate}
	// based on a heartbeat message acknowledgement counter peer should
	// know when the voting round should be ended
	while(roundNotEnded()) {
		// get the vote requests received since the last heartbeat
		S = getNewCandidates()
		if (empty(S)) {
			// if no request received then check if the support 
			// service has provided some candidate info 
			stat = getLastHeartbeatStat()
			if (stat.candadate != nil) {
				S = {probeCandidate(stat.candidate, stat.probingToken)}
			}
		}
		// in case there are malicious front-runners that are 
		// eliminated in the last round but still seeking votes, do
		// a sanity filtering of incoming candidate set
		F = filterCandidateByRound(S, round)
		b = selectBest(F)
		if (b != nil && !contains(knownCandidates, b)
				&& (currC = nil || isBetter(b, currC))) {
			// change vote if the new candiate is better
			updateLedger(b)
			currC = b
			currVCert = castVote(b)
			knownCandidates =  knownCandidates + {b}
			// encourage all neighbors to switch to the chosen
			// candidate by sending them sub-token
			seekVotesFromNeighbors(b, getAllNeighbors())
		} else if (currC != nil) {
			// keep the current vote intact with the support service
			currVCert = retainVote()
			// if there is any new peer connections then influence
			// them to support the chosen candidate
			nn = getNewNeighbors()
			seekVotesFromNeighbors(currC, nn)
		}
	}
	// reveal the encoded vote to the support service at the end of round
	revealVote(currC)
	return currVCert
}

func waitForConsensus(initialVoteCert, initialToken) {
	round = 0
	// a front-runner  will start with its own ledger version and token
	currToken = initialToken
	currVCert = initialVoteCert
	while (true) {
		// complete a voting round
		lastVoteCert = votingRound(currToken, currVCert, round)
		// check for majority consensus
		winner = verifySingleMajority()
		if (winner != nil) {
			// if consensus is reached then sync the chain, get the
			// checkpoint block, and break the loop
			if (latVoteCert.candidate == winner) {
				block = getCheckpointBlock()
				addCheckpointBlock(ledger, block)
				break
			} else {
				syncWithWinner(winner)
				break
			}
		} else {
			// otherwise prepare for the next round
			round++
			if (eliminated(lastVoteCert, round)) {
				currToken, currVCert = nil
			}
		}
	}
}

func roundNotEnded() {
	// retrieve information from the latest heartbeat acknowledgement
	stat = getLastHeartbeatAckStat()
	// if support service has not declared that checkpoint protocol has
	// started then checkpoint voting can continue for arbitrary long
	if (stat.mode != CHEK_POINTING_INITATED) return true
	// otherwise round continues until the support service checkpoint 
	// round counter reaches 0
	return (stat.counter > 0)
}

