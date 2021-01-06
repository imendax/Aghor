rule signature_117
{
	meta:
		authro = "0xlsd"
		sample = "ddb912efde5ca4e9fa3c6be2b93b62d7808a0ddc6d0ccc248a0927454b66bcba"
	
	
	strings:
		$string_1 = {
			17
			16
			15 14 13 12 11
			10 0F
			0E
			0D 0C 0B 0A 09
			08 07
			06
			05 04 03 02 01
			00 FF
		}
	
	condition:
		any of them
	
}
