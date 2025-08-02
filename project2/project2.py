import cv2
import numpy as np
import matplotlib.pyplot as plt

def load_image(path):
    """加载图像并确保为三通道"""
    img = cv2.imread(path)
    if img is None:
        raise ValueError(f"无法加载图像: {path}")
    return img

def tobits(text):
    """将字符串转换为二进制序列，包含终止符"""
    bits = []
    # 添加终止符'\0'以标记文本结束
    text += '\0'
    for char in text:
        b = bin(ord(char))[2:].zfill(8)  # 8位二进制表示
        bits.extend([int(bit) for bit in b])
    return bits

def totext(bits):
    """从二进制序列恢复字符串，遇到终止符停止"""
    chars = []
    for i in range(0, len(bits), 8):
        if i + 8 > len(bits):
            break
        byte = bits[i:i+8]
        char_val = int(''.join(str(b) for b in byte), 2)
        if char_val == 0:  # 遇到终止符
            break
        chars.append(chr(char_val))
    return ''.join(chars)

def embed_wm(img, text):
    """在图像中嵌入水印（使用蓝色通道LSB）"""
    bits = tobits(text)
    if len(bits) > img.shape[0] * img.shape[1]:
        raise ValueError("水印太大，无法嵌入图像")
    
    # 创建副本并分离通道
    wm_img = img.copy()
    b, g, r = cv2.split(wm_img)
    flat_b = b.flatten()
    
    # 嵌入水印到LSB
    for i in range(len(bits)):
        flat_b[i] = (flat_b[i] & 0xFE) | bits[i]
    
    # 重构图像
    b_embedded = flat_b.reshape(b.shape)
    return cv2.merge([b_embedded, g, r])

def extract_wm(img, original_shape=None):
    """从图像中提取水印，支持多种变换恢复"""
    processed_img = img.copy()
    
    # 如果是水平翻转图像则恢复
    if original_shape and img.shape[:2] != original_shape[:2]:
        processed_img = cv2.resize(img, (original_shape[1], original_shape[0]))
    
    # 提取蓝色通道LSB
    b_channel = processed_img[:, :, 0]
    bits = (b_channel.flatten() & 1).tolist()
    
    # 提取文本
    text = totext(bits)
    return text

# 鲁棒性测试函数
def test_robustness(wm_img, original_shape, test_name, operation):
    """执行鲁棒性测试并显示结果"""
    test_img = operation(wm_img.copy())
    extracted = extract_wm(test_img, original_shape)
    print(f"{test_name}测试提取: {extracted}")
    return test_img

# 测试操作定义
def flip_operation(img):
    return cv2.flip(img, 1)  # 水平翻转

def translate_operation(img):
    M = np.float32([[1, 0, 50], [0, 1, 30]])  # 平移(50,30)
    return cv2.warpAffine(img, M, (img.shape[1], img.shape[0]))

def crop_operation(img):
    return img[50:350, 100:400]  # 截取部分区域

def contrast_operation(img):
    return cv2.convertScaleAbs(img, alpha=1.5, beta=0)  # 增加对比度

def noise_operation(img):
    noise = np.random.normal(0, 25, img.shape).astype(np.uint8)
    return cv2.add(img, noise)  # 添加高斯噪声

# ===== 主程序 =====
if __name__ == "__main__":
    # 1. 加载原始图像
    original_img = load_image('origin.png')
    original_shape = original_img.shape
    print(f"原始图像尺寸: {original_shape}")
    
    # 2. 嵌入水印
    watermark_text = "SDUCST"
    wm_img = embed_wm(original_img, watermark_text)
    cv2.imwrite('watermarked.png', wm_img)
    
    # 3. 正常提取测试
    extracted_normal = extract_wm(wm_img, original_shape)
    print(f"正常提取结果: {extracted_normal}")
    
    # 4. 鲁棒性测试
    print("\n=== 鲁棒性测试 ===")
    flip_img = test_robustness(wm_img, original_shape, "水平翻转", flip_operation)
    translate_img = test_robustness(wm_img, original_shape, "平移", translate_operation)
    crop_img = test_robustness(wm_img, original_shape, "截取", crop_operation)
    contrast_img = test_robustness(wm_img, original_shape, "对比度调整", contrast_operation)
    noise_img = test_robustness(wm_img, original_shape, "噪声添加", noise_operation)
    
    # 5. 保存测试图像
    cv2.imwrite('test_flip.png', flip_img)
    cv2.imwrite('test_translate.png', translate_img)
    cv2.imwrite('test_crop.png', crop_img)
    cv2.imwrite('test_contrast.png', contrast_img)
    cv2.imwrite('test_noise.png', noise_img)
    
    print("\n所有测试完成，结果图像已保存")
