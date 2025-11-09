import os
import numpy as np
import librosa
import joblib  # Scaler(LSTM) 로드
import tempfile
import wave
import pefile
# TensorFlow/Keras에서 'pad_sequences' 유틸리티만 빌려옵니다.
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.preprocessing import StandardScaler

# --- 1. 전역 설정 (LSTM + CNN) ---

# (LSTM용 설정)
WAV_CONFIG = {
    'CHANNELS': 1,      # 1: 모노
    'SAMPWIDTH': 1,     # 1: 8-bit (1바이트)
    'FRAMERATE': 32768  # 32768Hz
}
SAMPLING_RATE = WAV_CONFIG['FRAMERATE']
MAX_LEN = 800
FEATURE_DIM = 58 # (rms(1) + spec_centroid(1) + spec_contrast(7) + mel_spec(40) + mfcc(9) = 58)
SCALER_PATH = 'models/scaler.joblib'

# (CNN용 설정)
IMAGE_WIDTH = 512 # 512x512
TARGET_SECTIONS = ['.text', '.rdata', '.data', '.rsrc']


# --- 2. (HELPER) EXE -> WAV 변환 (LSTM용) ---
def convert_exe_to_wav(exe_path):
    """(LSTM용) EXE 파일의 원본 바이트를 8-bit, 32768Hz 모노 WAV 파일로 변환."""
    try:
        with open(exe_path, 'rb') as f:
            binary_data = f.read()
        if not binary_data:
            raise ValueError("파일이 비어있습니다 (0KB).")
    except Exception as e:
        print(f"[Analyzer-LSTM] EXE 파일 로드 실패: {e}")
        raise

    temp_wav_path = None
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.wav')
        temp_wav_path = temp_file.name
        temp_file.close()
        
        frame_bytes = WAV_CONFIG['SAMPWIDTH'] * WAV_CONFIG['CHANNELS']
        if len(binary_data) % frame_bytes != 0:
            pad_len = frame_bytes - (len(binary_data) % frame_bytes)
            binary_data += (b'\x00' * pad_len)
            
        with wave.open(temp_wav_path, 'wb') as wav_file:
            wav_file.setnchannels(WAV_CONFIG['CHANNELS'])
            wav_file.setsampwidth(WAV_CONFIG['SAMPWIDTH'])
            wav_file.setframerate(WAV_CONFIG['FRAMERATE'])
            wav_file.writeframes(binary_data)
        return temp_wav_path
    except Exception as e:
        print(f"[Analyzer-LSTM] WAV 파일 쓰기 오류: {e}")
        if temp_wav_path and os.path.exists(temp_wav_path):
            os.remove(temp_wav_path)
        raise

# --- 3. (HELPER) WAV -> 특징 추출 (LSTM용) ---
def extract_features_from_wav(file_path):
    """(LSTM용) .wav 파일을 읽어와서 58개의 특징(feature)을 추출."""
    try:
        y, sr = librosa.load(file_path, sr=SAMPLING_RATE)
        mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=20).T
        rms = librosa.feature.rms(y=y).T
        spec_centroid = librosa.feature.spectral_centroid(y=y, sr=sr).T
        spec_contrast = librosa.feature.spectral_contrast(y=y, sr=sr).T
        mel_spec = librosa.feature.melspectrogram(y=y, sr=sr, n_mels=40).T
        selected_mfcc = mfcc[:, [0, 1, 2, 3, 4, 9, 13, 17, 19]]

        min_len = min(rms.shape[0], spec_centroid.shape[0], spec_contrast.shape[0], mel_spec.shape[0], selected_mfcc.shape[0])
        if min_len == 0:
            raise ValueError("특징 추출 결과 길이가 0입니다 (파일이 너무 작음).")

        rms, spec_centroid, spec_contrast, mel_spec, selected_mfcc = \
            rms[:min_len], spec_centroid[:min_len], spec_contrast[:min_len], mel_spec[:min_len], selected_mfcc[:min_len]

        features = np.concatenate(
            [rms, spec_centroid, spec_contrast, mel_spec, selected_mfcc], axis=1
        )
        return features
    except Exception as e:
        print(f"[Analyzer-LSTM] WAV 특징 추출 실패: {e}")
        raise

# --- 4. (HELPER) EXE -> 이미지 배열 추출 (CNN용) ---
def extract_cnn_features(file_path: str) -> np.ndarray | None:
    """
    (CNN용) PE 파일에서 섹션 바이트를 추출하여 (IMAGE_WIDTH, IMAGE_WIDTH) 크기의
    2D Numpy 배열(0-255 범위)로 반환
    """
    try:
        pe = pefile.PE(file_path, fast_load=True)
        final_bytes = b''
        
        for section in pe.sections:
            try:
                section_name = section.Name.decode('latin-1').strip('\x00')
                if section_name in TARGET_SECTIONS:
                    final_bytes += section.get_data()
            except Exception:
                continue
        pe.close()

        if not final_bytes:
            print(f"[Analyzer-CNN] 경고: {file_path}에서 유의미한 섹션 데이터를 찾을 수 없음 (패킹 의심)")
            return None

        image_size = IMAGE_WIDTH * IMAGE_WIDTH
        
        if len(final_bytes) > image_size:
            final_bytes = final_bytes[:image_size]
        else:
            padding_size = image_size - len(final_bytes)
            final_bytes += b'\x00' * padding_size

        image_array = np.frombuffer(
            final_bytes, dtype=np.uint8
        ).reshape((IMAGE_WIDTH, IMAGE_WIDTH))
        
        # Keras 모델이 Rescaling 레이어를 내장하고 있으므로 (0-255) 원본 배열 반환
        return image_array

    except pefile.PEFormatError:
        print(f"[Analyzer-CNN] 오류: {file_path}는 PE 파일이 아닙니다.")
        return None
    except Exception as e:
        print(f"[Analyzer-CNN] 심각한 오류 발생 ({file_path}): {e}")
        return None

# --- 5. Scaler 로더 (LSTM용) ---
def load_scaler(scaler_path=SCALER_PATH):
    """학습 때 저장한 StandardScaler(scaler.joblib)를 로드합니다."""
    try:
        scaler = joblib.load(scaler_path)
        print(f"[Analyzer] '{scaler_path}'에서 Scaler 로드 성공.")
        return scaler
    except FileNotFoundError:
        print(f"[Analyzer 오류] Scaler 파일을 찾을 수 없습니다: {scaler_path}")
        return None
    except Exception as e:
        print(f"[Analyzer 오류] Scaler 로드 중 오류: {e}")
        return None

# --- 6. (INTERNAL) LSTM Numpy 배열 생성 파이프라인 ---
def _analyze_lstm_numpy(exe_path, scaler):
    """(LSTM용) EXE 파일을 받아 LSTM 모델용 Numpy 배열로 변환"""
    temp_wav_path = None
    try:
        temp_wav_path = convert_exe_to_wav(exe_path)
        features = extract_features_from_wav(temp_wav_path)
        
        # 1. Padding (Numpy 배열)
        padded_features = pad_sequences(
            [features], maxlen=MAX_LEN, padding='post', truncating='post', dtype='float32'
        )[0] # (MAX_LEN, 58) 크기의 Numpy 배열
        
        # 2. Scaling (Numpy 배열)
        scaled_features = scaler.transform(padded_features)
        
        # [수정] PyTorch 텐서 변환 로직 제거. Numpy 배열 자체를 반환.
        return scaled_features
    
    except Exception as e:
        # 오류는 각 helper 함수에서 이미 출력됨
        return None
    finally:
        if temp_wav_path and os.path.exists(temp_wav_path):
            try: os.remove(temp_wav_path)
            except Exception: pass

# --- 7. (PUBLIC) 메인 분석 함수 (앙상블용) ---
def analyze_file(exe_path, scaler):
    """
    하나의 EXE 파일을 받아 LSTM과 CNN 모델이 예측할 수 있는
    'Numpy 배열' 딕셔너리를 반환합니다.
    """
    if scaler is None:
        print("[Analyzer] Scaler 객체가 None입니다. Scaler 로드에 실패했습니다.")
        return None
        
    lstm_numpy_data = None
    cnn_numpy_data = None
    
    try:
        # 1. LSTM Numpy 데이터 생성 (800, 58)
        lstm_numpy_data = _analyze_lstm_numpy(exe_path, scaler)
        if lstm_numpy_data is None:
            raise ValueError("[Analyzer] LSTM 특징 추출 실패")

        # 2. CNN Numpy 데이터 생성 (512, 512)
        cnn_numpy_data = extract_cnn_features(exe_path)
        if cnn_numpy_data is None:
            raise ValueError("[Analyzer] CNN 특징 추출 실패")
        
        # Keras/PyTorch가 모두 알아듣는 Numpy 배열 딕셔너리 반환
        return {
            "lstm": lstm_numpy_data, 
            "cnn": cnn_numpy_data    
        }

    except Exception as e:
        print(f"앙상블 분석 파이프라인 오류 ({exe_path}): {e}")
        return None

# --- 8. 테스트용 실행 블록 ---
# if __name__ == "__main__":
#     print("--- Analyzer (Ensemble / Numpy) 모듈 테스트 시작 ---")
#     scaler = load_scaler(SCALER_PATH)
#     if scaler:
#         TEST_EXE_PATH = r"C:\Windows\System32\calc.exe" # 예시: 계산기
#         if not os.path.exists(TEST_EXE_PATH):
#              print(f"테스트 파일 '{TEST_EXE_PATH}'를 찾을 수 없습니다.")
#         else:
#             print(f"\n'{TEST_EXE_PATH}' 파일 분석 시도...")
#             data_dict = analyze_file(TEST_EXE_PATH, scaler)
            
#             if data_dict:
#                 print("\n--- 최종 Numpy 딕셔너리 생성 성공 ---")
#                 print(f"LSTM Numpy Shape: {data_dict['lstm'].shape}")
#                 print(f"CNN Numpy Shape: {data_dict['cnn'].shape}")
#             else:
#                 print("\n--- Numpy 딕셔너리 생성 실패 ---")
#     else:
#         print("\n--- 테스트 실패: Scaler 로드에 실패하여 분석을 진행할 수 없습니다. ---")