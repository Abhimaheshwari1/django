import hashlib
from .models import Block  # Import the Block model

class Blockchain:
    def __init__(self):
        # Initialize the chain and add the genesis block if no blocks exist
        self.chain = Block.objects.all().order_by('index')  # Fetch all blocks in order
        if not self.chain.exists():
            self.create_genesis_block()

    def create_genesis_block(self):
        # Create the first block in the blockchain (index 0)
        genesis_block = Block.objects.create(
            index=0,
            data='Genesis Block',  # Data for the genesis block
            previous_hash='0',
            current_hash=self.calculate_hash(0, 'Genesis Block', '0', 0)
        )
        return genesis_block

    def create_block(self, data):
        # Get the last block
        last_block = self.chain.last()

        # Create a new block
        new_block = Block(
            index=last_block.index + 1,
            data=data,  # Assuming this is already encrypted
            previous_hash=last_block.current_hash,
            current_hash='',
        )

        # Calculate the current block's hash
        new_block.current_hash = self.calculate_hash(new_block.index, new_block.data, new_block.previous_hash, 0)
        new_block.save()

        return new_block

    def calculate_hash(self, index, data, previous_hash, nonce):
        # Concatenate block fields and hash them using SHA-256
        value = f"{index}{data}{previous_hash}{nonce}"
        return hashlib.sha256(value.encode()).hexdigest()
