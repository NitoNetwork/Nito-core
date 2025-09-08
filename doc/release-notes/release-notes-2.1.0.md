- v2.1.0 Release Notes

Mandatory Consensus Upgrade
This release introduces a change to the block subsidy schedule. All nodes and miners must upgrade to v2.1.0 before the activation height to remain on the main chain.


- Block Subsidy Schedule Adjusted:
The block reward schedule has been updated with new boundary heights
This change slightly shifts the halving points forward or backward compared to previous releases.

- Previous schedule (v2.0.2 and earlier):
 0 – 525,599: 512 coins
 525,600 – 1,051,199: 256 coins
 1,051,200 – 1,576,799: 128 coins
 1,576,800 – 5,255,999: 64 coins
 5,256,000 – 10,511,999: 32 coins
 10,512,000 – 26,279,999: 16 coins
 26,280,000 – 105,120,000: 2 coins
 After 105,120,000: 0 coins

- Updated schedule (v2.1.0):
 0 – 529,999: 512 coins
 530,000 – 1,042,399: 256 coins
 1,042,400 – 1,576,799: 128 coins
 1,576,800 – 5,255,999: 64 coins
 5,256,000 – 10,511,999: 32 coins
 10,512,000 – 26,279,999: 16 coins
 26,280,000 – 105,120,000: 2 coins
 After 105,120,000: 0 coins


- Upgrade Notice:
 This is a mandatory hard fork.
 All miners, exchanges, and full nodes must upgrade to v2.1.0 to stay on the main chain.
 Running an older version after activation will result in chain splits and rejected blocks

- Technical Details
 Code change: `GetBlockSubsidy()` logic rewritten with explicit `if/else if` ranges and adjusted thresholds.
 Previous redundant `return` statements were cleaned up.
 Consensus impact: subsidy boundaries changed, affecting reward distribution.

