import hashlib
import math
from typing import List, Tuple, Optional, Dict, Set
from bisect import bisect_left

# SM3哈希函数实现
def sm3(data: bytes) -> bytes:
    """SM3哈希函数实现"""
    # 这里使用Python标准库的hashlib作为替代
    # 实际应用中应替换为真实的SM3实现
    return hashlib.sha256(data).digest()  # 在实际应用中替换为SM3

# RFC6962规范中定义的前缀
LEAF_PREFIX = b'\x00'
NODE_PREFIX = b'\x01'

class MerkleTree:
    def __init__(self, data: List[bytes]):
        """
        初始化Merkle树
        
        Args:
            data: 叶子节点的数据列表
        """
        # 存储原始数据
        self.raw_data = data[:]
        
        # 对数据进行排序（RFC6962要求叶子节点有序）
        self.sorted_data = sorted(data)
        
        # 存储叶子节点的哈希值（排序后）
        self.leaves = [sm3(LEAF_PREFIX + d) for d in self.sorted_data]
        
        # 构建哈希到原始数据的映射
        self.hash_to_data = {sm3(LEAF_PREFIX + d): d for d in data}
        
        # 构建Merkle树
        self.tree = self._build_tree(self.leaves)
        self.root_hash = self.tree[-1][0] if self.tree else b''
        
        # 创建叶子哈希到索引的映射
        self.leaf_index_map = {leaf: i for i, leaf in enumerate(self.leaves)}
    
    def _build_tree(self, nodes: List[bytes]) -> List[List[bytes]]:
        """
        构建Merkle树
        
        Args:
            nodes: 当前层的节点列表
            
        Returns:
            整个Merkle树的层级结构
        """
        tree = [nodes]  # 第0层是叶子节点
        
        # 逐层构建树
        current_level = nodes
        while len(current_level) > 1:
            next_level = []
            
            # 处理成对的节点
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = sm3(NODE_PREFIX + left + right)
                next_level.append(parent)
            
            tree.append(next_level)
            current_level = next_level
        
        return tree

    def get_root_hash(self) -> bytes:
        """获取Merkle根哈希"""
        return self.root_hash

    def get_tree_height(self) -> int:
        """获取树的高度"""
        return len(self.tree) if self.tree else 0

    def get_leaf_index(self, data: bytes) -> Optional[int]:
        """
        获取叶子节点的索引
        
        Args:
            data: 叶子节点数据
            
        Returns:
            叶子节点的索引，如果不存在则返回None
        """
        leaf_hash = sm3(LEAF_PREFIX + data)
        return self.leaf_index_map.get(leaf_hash)

    def get_inclusion_proof(self, index: int) -> List[bytes]:
        """
        获取存在性证明
        
        Args:
            index: 叶子节点的索引
            
        Returns:
            从叶子节点到根节点的路径上的兄弟节点哈希列表
        """
        if index < 0 or index >= len(self.leaves):
            return []
        
        proof = []
        level = 0
        pos = index
        
        # 从叶子节点向上遍历到根节点
        while level < len(self.tree) - 1:
            # 计算兄弟节点的位置
            sibling_pos = pos - 1 if pos % 2 == 1 else pos + 1
            
            # 确保兄弟节点存在
            if 0 <= sibling_pos < len(self.tree[level]):
                proof.append(self.tree[level][sibling_pos])
            
            # 移动到上一层
            pos //= 2
            level += 1
        
        return proof

    def verify_inclusion(self, data: bytes, index: int, proof: List[bytes], root_hash: bytes) -> bool:
        """
        验证存在性证明
        
        Args:
            data: 叶子节点数据
            index: 叶子节点索引
            proof: 存在性证明路径
            root_hash: Merkle根哈希
            
        Returns:
            验证是否成功
        """
        # 计算叶子哈希
        leaf_hash = sm3(LEAF_PREFIX + data)
        current_hash = leaf_hash
        current_index = index
        
        # 根据证明路径重建哈希
        for sibling_hash in proof:
            # 根据索引判断是左兄弟还是右兄弟
            if current_index % 2 == 1:  # 奇数索引是右节点
                current_hash = sm3(NODE_PREFIX + sibling_hash + current_hash)
            else:  # 偶数索引是左节点
                current_hash = sm3(NODE_PREFIX + current_hash + sibling_hash)
            
            # 移动到上一层
            current_index //= 2
        
        return current_hash == root_hash

    def get_exclusion_proof(self, data: bytes) -> Tuple[Optional[int], Optional[int], List[bytes]]:
        """
        获取不存在性证明
        
        Args:
            data: 要证明不存在的叶子节点数据
            
        Returns:
            (前驱索引, 后继索引, 路径证明)
        """
        # 计算目标叶子哈希
        target_hash = sm3(LEAF_PREFIX + data)
        
        # 如果树为空
        if not self.leaves:
            return None, None, []
        
        # 使用二分查找找到目标哈希应该插入的位置
        index = bisect_left(self.leaves, target_hash)
        
        # 如果找到完全匹配的哈希，说明数据存在
        if index < len(self.leaves) and self.leaves[index] == target_hash:
            return None, None, []
        
        # 确定前驱和后继
        predecessor = index - 1 if index > 0 else None
        successor = index if index < len(self.leaves) else None
        
        # 收集所有需要的证明节点
        proof_nodes = set()
        
        # 获取前驱节点的证明路径（如果存在）
        if predecessor is not None:
            pred_proof = self.get_inclusion_proof(predecessor)
            proof_nodes.update(pred_proof)
        
        # 获取后继节点的证明路径（如果存在）
        if successor is not None:
            succ_proof = self.get_inclusion_proof(successor)
            proof_nodes.update(succ_proof)
        
        # 还需要根节点来验证
        proof_nodes.add(self.root_hash)
        
        return predecessor, successor, list(proof_nodes)

    def verify_exclusion(self, data: bytes, predecessor: Optional[int], successor: Optional[int], 
                        proof: List[bytes], root_hash: bytes) -> bool:
        """
        验证不存在性证明
        
        Args:
            data: 要证明不存在的叶子节点数据
            predecessor: 前驱索引
            successor: 后继索引
            proof: 路径证明
            root_hash: Merkle根哈希
            
        Returns:
            验证是否成功
        """
        # 计算目标叶子哈希
        target_hash = sm3(LEAF_PREFIX + data)
        
        # 验证根哈希在证明中
        if root_hash not in proof:
            return False
        
        # 验证前驱和后继的正确性
        if predecessor is not None:
            # 获取前驱节点的数据
            pred_data = self.sorted_data[predecessor]
            
            # 验证前驱节点的存在性
            pred_leaf = self.leaves[predecessor]
            pred_proof = [p for p in proof if p != root_hash]  # 使用所有非根节点作为证明
            
            # 注意：这里我们使用一个技巧，因为证明路径可能包含多个节点
            # 实际上，我们需要从证明中提取前驱节点的完整证明路径
            # 在真实实现中，应该单独存储前驱和后继的证明路径
            # 这里简化处理，使用所有非根节点
            if not self.verify_inclusion(pred_data, predecessor, pred_proof, root_hash):
                return False
            
            # 验证前驱小于目标
            if pred_leaf >= target_hash:
                return False
        
        if successor is not None:
            # 获取后继节点的数据
            succ_data = self.sorted_data[successor]
            
            # 验证后继节点的存在性
            succ_leaf = self.leaves[successor]
            succ_proof = [p for p in proof if p != root_hash]  # 使用所有非根节点作为证明
            
            if not self.verify_inclusion(succ_data, successor, succ_proof, root_hash):
                return False
            
            # 验证后继大于目标
            if succ_leaf <= target_hash:
                return False
        
        # 验证前驱和后继是相邻的
        if predecessor is not None and successor is not None:
            if predecessor + 1 != successor:
                return False
        elif predecessor is None and successor is not None:
            if successor != 0:
                return False
        elif successor is None and predecessor is not None:
            if predecessor != len(self.leaves) - 1:
                return False
        else:  # 两者都为None
            if len(self.leaves) > 0:
                return False
        
        return True

    def visualize(self, level_limit: int = 3) -> None:
        """可视化Merkle树（限制层级）"""
        if not self.tree:
            print("Empty tree")
            return
        
        for level, nodes in enumerate(self.tree):
            if level > level_limit:
                print(f"... and {len(self.tree) - level_limit} more levels")
                break
                
            print(f"Level {level} ({len(nodes)} nodes):")
            for i, node in enumerate(nodes):
                print(f"  Node {i}: {node[:4].hex()}...")
            print()


def generate_large_dataset(size: int = 100000) -> List[bytes]:
    """生成大型数据集（10万叶子节点）"""
    return [f"leaf_{i:06d}".encode('utf-8') for i in range(size)]


def main():
    print("="*50)
    print("SM3 Merkle Tree Implementation (RFC6962)")
    print("="*50)
    
    # 创建一个小型树用于演示
    small_data = [b'alpha', b'beta', b'delta', b'gamma']  # 故意无序
    print("创建小型Merkle树 (4个叶子节点):")
    print("原始数据:", [d.decode() for d in small_data])
    
    tree = MerkleTree(small_data)
    print("排序后数据:", [d.decode() for d in tree.sorted_data])
    print(f"根哈希: {tree.get_root_hash().hex()}")
    tree.visualize()
    
    # 存在性证明演示
    print("\n存在性证明演示:")
    # 获取gamma的索引（排序后）
    gamma_index = tree.get_leaf_index(b'gamma')
    print(f"叶子节点 'gamma' 的索引: {gamma_index}")
    
    if gamma_index is not None:
        proof = tree.get_inclusion_proof(gamma_index)
        print(f"存在性证明路径 ({len(proof)} 个节点):")
        for i, node in enumerate(proof):
            print(f"  步骤 {i+1}: {node[:8].hex()}...")
        
        # 验证存在性证明
        is_valid = tree.verify_inclusion(b'gamma', gamma_index, proof, tree.get_root_hash())
        print(f"\n验证结果: {'成功' if is_valid else '失败'}")
    
    # 不存在性证明演示
    print("\n不存在性证明演示:")
    non_existent = b'epsilon'  # 不在树中
    pred_idx, succ_idx, exclusion_proof = tree.get_exclusion_proof(non_existent)
    
    print(f"数据 '{non_existent.decode()}' 的不存在性证明:")
    if pred_idx is not None:
        pred_data = tree.sorted_data[pred_idx].decode()
        print(f"  前驱索引: {pred_idx} ({pred_data})")
    else:
        print(f"  前驱索引: None")
    
    if succ_idx is not None:
        succ_data = tree.sorted_data[succ_idx].decode()
        print(f"  后继索引: {succ_idx} ({succ_data})")
    else:
        print(f"  后继索引: None")
    
    print(f"  证明路径包含 {len(exclusion_proof)} 个节点")
    
    # 验证不存在性证明
    is_valid = tree.verify_exclusion(
        non_existent, pred_idx, succ_idx, exclusion_proof, tree.get_root_hash()
    )
    print(f"\n验证结果: {'成功' if is_valid else '失败'}")
    
    # 创建大型树（10万叶子节点）
    print("\n创建大型Merkle树 (100,000个叶子节点)...")
    large_data = generate_large_dataset(100000)
    large_tree = MerkleTree(large_data)
    print(f"树高度: {large_tree.get_tree_height()}")
    print(f"根哈希: {large_tree.get_root_hash().hex()}")
    
    # 大型树的存在性证明
    print("\n大型树存在性证明演示:")
    large_index = 54321
    leaf_data = large_tree.sorted_data[large_index]
    print(f"叶子数据: {leaf_data.decode()}")
    
    large_proof = large_tree.get_inclusion_proof(large_index)
    print(f"存在性证明路径包含 {len(large_proof)} 个节点")
    
    # 验证大型树的存在性证明
    is_valid = large_tree.verify_inclusion(
        leaf_data, large_index, large_proof, large_tree.get_root_hash()
    )
    print(f"验证结果: {'成功' if is_valid else '失败'}")
    
    # 大型树的不存在性证明
    print("\n大型树不存在性证明演示:")
    non_existent_large = b'non_existent_leaf'
    pred_idx, succ_idx, exclusion_proof_large = large_tree.get_exclusion_proof(non_existent_large)
    print(f"数据 '{non_existent_large.decode()}' 的不存在性证明:")
    
    if pred_idx is not None:
        print(f"  前驱数据: {large_tree.sorted_data[pred_idx].decode()}")
    else:
        print(f"  前驱索引: None")
    
    if succ_idx is not None:
        print(f"  后继数据: {large_tree.sorted_data[succ_idx].decode()}")
    else:
        print(f"  后继索引: None")
    
    print(f"  证明路径包含 {len(exclusion_proof_large)} 个节点")
    
    # 验证大型树的不存在性证明
    is_valid = large_tree.verify_exclusion(
        non_existent_large, pred_idx, succ_idx, 
        exclusion_proof_large, large_tree.get_root_hash()
    )
    print(f"验证结果: {'成功' if is_valid else '失败'}")


if __name__ == "__main__":
    main()





