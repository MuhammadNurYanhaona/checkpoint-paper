func miningModeHeartbeatProcessor(heartbeat, miner) {
	// if the miner is earlier detected to be malicious ignore it
	if (blacklisted(miner)) return NACK
	// verify PoW
	if (powVerificationFailed(miner, heartbeat)) {
		blacklistMiner(miner)
		return NACK
	}
	// a peer can send encoded vote to record when everyone else is in the 
	// block mining mode
	if (heartbeat.type == CHECKPOINT_VOTE) {
		// to record a vote the peer must be considered active beforehand
		if (!recordedAsActive(miner)) {
			return NACK
		}
		// update the last communication time of the peer
		updateLastExchangeTime(miner)
		// record the vote and generate an vote reception acknowledgement 
		// certificate
		vCert = recordEncodedVote(heartbeat.vote)
		// if 50% miners recorded vote then migrate to checkpoint 
		// consensus process
		N = getMinerCountEstimate()
		c = countCastBallots()
		if (c >= N/2) {
			initiateCheckpointConsensus()
		}
		// generate challenge text for vote change PoW 
		chal = generateVoteChangeChallenge(vCert, miner)
		// send acknowledgement
		return new VoteAccecptAck(vCert, chal)

	} else  {
		// update the last communication time
		updateLastExchangeTime(miner)
		// send acknowledgement for heartbeat message
		ack = generateAck(heartbeat)
		chal = generateHeartbeatChallenge(heartbeat, miner)
		return new HeartbeatAck(ack, chal)
	}
}


func initiateCheckpointConsensus() {
	// launch an alternative heartbeat message processor when in the
	// checkpoint consensus mode
	setHeartbeatProcessor(checkpointHeartbeatProcessor)
	// first voting round will continue for N/2 ticks of support service
	// clock timer
	N = getMinerCountEstimate()
	votingRoundTerminator = initCountDownCounter(N/2)
	consensusEstablished = false

	do {
		// wait for the voting round to end
		waitForReachingZero(votingRoundTerminator)
		// set the heartbeat processor to vote decoding mode	
		setHeartbeatProcessor(voteRevealHeartbeatProcessor)
		// wait for vote revelation to end
		voteRevelationCounter = initCountDownCounter(ACTIVATION_WINDOW)
		waitForReachingZero(voteRevelationCounter)

		stat = checkForSingleMajority()
		if (stat == true) {
			// in case a single majority is detected then consensus is
			// established; publish checkpoint block sealing material
			// to be retrieved by the mining nodes
			publishResultWithSealingMaterial()
			consensusEstablished = true
		} else {
			// if no single majority consensus is reached in this round
			// then publish the verifiable filtering criteria
			publishResultWithCandidateFilter()
			// reset the vote collection counter to allow N clock ticks 
			// for the next round
			resetCounterTo(N)
			// reset the heartbeat processor to vote recording mode
			setHeartbeatProcessor(checkpointHeartbeatProcessor)
		}
	} while(!consensusEstablished)

	// reset database and advance to the checkpoint interval
	clearVoteDatabase()
	updateCheckpointCounter()
	// resume normal interaction
	setHeartbeatProcessor(miningModeHeartbeatProcessor)
}

func checkpointHeartbeatProcessor(heartbeat, miner) {
	// blacklisted peers and peers recorded as inactive before cannot 
	// participate in the checkpoint establishment process
	if (blacklisted(miner) || !recordedAsActive(miner)) return NACK
	// verify PoW
	if (powVerificationFailed(miner, heartbeat)) {
		blacklistMiner(miner)
		return NACK
	}
	// update the last communication time of the peer
	updateLastExchangeTime(miner)
	// heartbeat from a lagging behind mining peer who does not know 
	// about ongoing check-pointing process
	if (heartbeat.type = MINING_HEARTBEAT) {
		// get the next batch of existing voters from miner specific 
		// permutation of the voting population
		suggestedCandidates = getNextBatchFromExistingVoters(miner)
		// update the last communication time of the peer
		updateLastExchangeTime(miner)
		// send reply
		ack = generateAck(heartbeat)
		chal = generateHeartbeatChallenge(heartbeat, miner)
		return new HeartbeatAck(ack, chal, suggestedCandidates)
	} else {
		vCert = recordEncodedVote(heartbeat.vote)
		chal = generateVoteChangeChallenge(vCert, miner)
		return new VoteAccecptAck(vCert, chal)
	}
}
