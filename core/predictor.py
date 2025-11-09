import os
import numpy as np

# --- 1. 프레임워크 임포트 (TensorFlow와 PyTorch 모두 사용) ---
try:
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2' # TensorFlow 로그 숨기기
    import tensorflow as tf
except ImportError:
    print("[Predictor 경고] TensorFlow가 설치되어 있지 않습니다. CNN 모델을 사용할 수 없습니다.")
    tf = None

try:
    import torch
    import torch.nn as nn
except ImportError:
    print("[Predictor 경고] PyTorch가 설치되어 있지 않습니다. LSTM 모델을 사용할 수 없습니다.")
    torch = None


# --- 2. 모델 경로 설정 ---
CNN_MODEL_PATH = "models/cnn_model.h5"   
LSTM_MODEL_PATH = "models/rnn_model.pth" 


# --- 3. PyTorch LSTM 모델 클래스 정의 ---
if torch:
    class LSTMModel(nn.Module):
        def __init__(self, input_size, hidden_size, num_layers, fc_size, num_classes, dropout):
            super(LSTMModel, self).__init__()
            self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True, bidirectional=True, dropout=dropout if num_layers > 1 else 0)
            self.attention = nn.Sequential(nn.Linear(hidden_size * 2, 128), nn.ReLU(), nn.Linear(128, 1))
            self.fc1 = nn.Linear(hidden_size * 2, fc_size)
            self.relu = nn.ReLU()
            self.dropout_layer = nn.Dropout(dropout)
            self.fc2 = nn.Linear(fc_size, num_classes)
            self.sigmoid = nn.Sigmoid()

        def forward(self, x):
            lstm_out, _ = self.lstm(x)
            attn_weights = torch.softmax(self.attention(lstm_out), dim=1)
            context_vector = torch.sum(attn_weights * lstm_out, dim=1)
            out = self.dropout_layer(self.relu(self.fc1(context_vector)))
            return self.sigmoid(self.fc2(out)).squeeze(1)


# --- 4. 앙상블 예측기 클래스 ---

class Predictor:
    """
    CNN(TensorFlow)과 LSTM(PyTorch) 모델을 모두 로드하고,
    앙상블 예측을 수행하는 통합 예측기 클래스.
    """
    def __init__(self):
        print("[Predictor] 앙상블 예측기 초기화 중...")
        self.device = torch.device('cpu') # PyTorch는 CPU 사용으로 고정 (map_location)
        self.cnn_model = self._load_cnn_model(CNN_MODEL_PATH)
        self.lstm_model = self._load_lstm_model(LSTM_MODEL_PATH)

    def _load_cnn_model(self, model_path):
        """내부 함수: Keras 모델 파일 로드"""
        if not tf: return None
        if not os.path.exists(model_path):
            print(f"[Predictor-CNN] 오류: 모델 파일({model_path})을 찾을 수 없습니다.")
            return None
        try:
            model = tf.keras.models.load_model(model_path)
            print(f"[Predictor-CNN] {model_path} 모델 로드 성공.")
            # Keras 모델 워밍업
            warmup_data = np.zeros((1, 512, 512, 1), dtype=np.float32)
            model.predict(warmup_data, verbose=0)
            print("[Predictor-CNN] 모델 워밍업 완료.")
            return model
        except Exception as e:
            print(f"[Predictor-CNN] {model_path} 로드 실패: {e}")
            return None

    def _load_lstm_model(self, model_path):
        """내부 함수: PyTorch 모델 파일 로드"""
        if not torch: return None
        if not os.path.exists(model_path):
            print(f"[Predictor-LSTM] 오류: 모델 파일({model_path})을 찾을 수 없습니다.")
            return None
        try:
            # CPU로 로드하도록 map_location 설정
            # ★★★ [수정] PyTorch 2.6+ 보안 정책으로 인해 weights_only=False 추가 ★★★
            checkpoint = torch.load(
                model_path, 
                map_location=self.device,
                weights_only=False  # <--- 이 옵션을 추가합니다!
            )
            model_config = checkpoint['config']
            model_state_dict = checkpoint['model_state_dict']
            
            model = LSTMModel(
                input_size=58, # analyzer.py와 일치
                hidden_size=model_config['hidden_size'],
                num_layers=model_config['num_layers'],
                fc_size=model_config['fc_size'],
                num_classes=model_config['num_classes'],
                dropout=model_config['dropout']
            )
            model.load_state_dict(model_state_dict)
            model.to(self.device) # 모델을 CPU로
            model.eval() # 추론 모드로 설정
            print(f"[Predictor-LSTM] {model_path} 모델 로드 성공.")
            return model
        except Exception as e:
            print(f"[Predictor-LSTM] {model_path} 로드 실패: {e}")
            return None


    def predict_cnn(self, image_array: np.ndarray) -> float | None:
        """
        analyzer가 생성한 (512, 512) Numpy 배열을 받아 악성 확률(float)을 반환.
        """
        if self.cnn_model is None:
            print("[Predictor-CNN] 모델이 로드되지 않아 예측 불가")
            return None
        try:
            # 1. Numpy 배열 -> Keras 텐서 변환
            # (512, 512) -> (1, 512, 512, 1)
            tensor = np.expand_dims(image_array, axis=-1) 
            tensor = np.expand_dims(tensor, axis=0)
            
            # 2. 예측
            # (모델 내부에 Rescaling(1./255) 레이어가 있으므로 원본(0-255) 배열 전달)
            prediction_output = self.cnn_model.predict(tensor, verbose=0)
            
            # 3. [0][1] (악성) 확률 추출
            malicious_prob = prediction_output[0][1] 
            return float(malicious_prob)
        except Exception as e:
            print(f"[Predictor-CNN] 예측 중 오류 발생: {e}")
            return None

    def predict_lstm(self, lstm_array: np.ndarray) -> float | None:
        """
        analyzer가 생성한 (800, 58) Numpy 배열을 받아 악성 확률(float)을 반환.
        """
        if self.lstm_model is None:
            print("[Predictor-LSTM] 모델이 로드되지 않아 예측 불가")
            return None
        try:
            with torch.no_grad():
                # 1. Numpy 배열 -> PyTorch 텐서 변환
                tensor = torch.tensor(lstm_array, dtype=torch.float32).to(self.device)
                # (800, 58) -> (1, 800, 58)
                tensor = tensor.unsqueeze(0) 

                # 2. 예측
                prediction_output = self.lstm_model(tensor)
                
                # 3. 확률(float) 반환
                return prediction_output.item()
        except Exception as e:
            print(f"[Predictor-LSTM] 예측 중 오류 발생: {e}")
            return None

    def predict_ensemble(self, data_dict: dict, weights={'cnn': 0.5, 'lstm': 0.5}) -> float | None:
        """
        analyzer가 생성한 'Numpy 딕셔너리'를 받아 최종 앙상블 확률을 반환.
        """
        cnn_prob = None
        lstm_prob = None

        # --- 1. CNN 예측 (Numpy -> Keras) ---
        if self.cnn_model and 'cnn' in data_dict:
            cnn_input_array = data_dict['cnn'] # (512, 512) Numpy
            cnn_prob = self.predict_cnn(cnn_input_array)

        # --- 2. LSTM 예측 (Numpy -> PyTorch) ---
        if self.lstm_model and 'lstm' in data_dict:
            lstm_input_array = data_dict['lstm'] # (800, 58) Numpy
            lstm_prob = self.predict_lstm(lstm_input_array)

        # --- 3. 앙상블 결과 조합 ---
        if cnn_prob is not None and lstm_prob is not None:
            # 둘 다 성공
            final_prob = (cnn_prob * weights['cnn']) + (lstm_prob * weights['lstm'])
            print(f"[Predictor-Ensemble] CNN={cnn_prob:.4f}, LSTM={lstm_prob:.4f} -> Final={final_prob:.4f}")
            return final_prob
        elif cnn_prob is not None:
            print("[Predictor-Ensemble] CNN만 예측 성공.")
            return cnn_prob # CNN만 성공
        elif lstm_prob is not None:
            print("[Predictor-Ensemble] LSTM만 예측 성공.")
            return lstm_prob # LSTM만 성공
        else:
            print("[Predictor-Ensemble] 모든 예측 실패.")
            return None # 둘 다 실패

# # --- 테스트용 실행 블록 ---
# if __name__ == "__main__":
#     print("--- Predictor (Ensemble / Numpy) 모듈 테스트 시작 ---")
#     predictor = Predictor()
    
#     if predictor.cnn_model or predictor.lstm_model:
#         # (analyzer.py의 Numpy 출력물 흉내)
#         dummy_lstm_array = np.random.rand(800, 58).astype(np.float32)
#         dummy_cnn_array = np.random.randint(0, 256, (512, 512), dtype=np.uint8)
        
#         dummy_data_dict = { "lstm": dummy_lstm_array, "cnn": dummy_cnn_array }
#         print("\n가상 Numpy 딕셔너리 생성 완료.")

#         final_probability = predictor.predict_ensemble(dummy_data_dict)
        
#         if final_probability is not None:
#             print("\n--- 앙상블 예측 성공 ---")
#             print(f"최종 예측 악성 확률: {final_probability*100:.2f} %")
#         else:
#             print("\n--- 앙상블 예측 실패 ---")
#     else:
#         print("\n테스트 실패: 모든 모델 로드에 실패했습니다.")