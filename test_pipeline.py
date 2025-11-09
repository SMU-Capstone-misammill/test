# test_pipeline.py
# (이 파일은 AI_Security_Agent/ 폴더에 위치해야 합니다)

import os
import time

# 1. '부품'들을 import 합니다.
from core.predictor import Predictor
#  analyze_file (메인 함수)와 load_scaler (필수)를 가져옵니다.
from core.analyzer import analyze_file, load_scaler


# 여기를 나중에 실시간으로 탐지하도록 해야함(watcher.py)


# --- [ ★ 유일하게 수정할 곳 ★ ] ---
# 테스트하고 싶은 실제 .exe 파일의 전체 경로를 입력하세요.
# (예: r"C:\Windows\System32\notepad.exe")
TEST_FILE_PATH = r"C:\Users\TaeGyeong\Downloads\ChromeSetup.exe"
# ------------------------------------

def run_test():
    """[수정] 앙상블 테스트 파이프라인을 순서대로 실행합니다."""

    # 0. 테스트 파일 존재 여부 확인 (유지)
    if not os.path.exists(TEST_FILE_PATH):
        print(f"[테스트 실패] 테스트 파일이 없습니다: {TEST_FILE_PATH}")
        return

    # 1. Predictor 객체 생성 (★ CNN + LSTM 모델 로딩 ★)
    print("--- 1. Predictor 객체 생성 (모델 로딩) ---")
    start_time = time.time()
    # 이 순간 core/predictor.py의 __init__이 실행됩니다.
    predictor = Predictor() 
    
    # [수정] 두 모델 중 하나라도 로드되었는지 확인
    if predictor.cnn_model is None and predictor.lstm_model is None:
        print("[테스트 실패] CNN과 LSTM 모델 모두 로딩에 실패했습니다.")
        return
    
    # (개별 확인)
    if predictor.cnn_model is None:
        print("[테스트 경고] CNN 모델 로딩 실패. LSTM으로만 테스트합니다.")
    if predictor.lstm_model is None:
        print("[테스트 경고] LSTM 모델 로딩 실패. CNN으로만 테스트합니다.")

    print(f"모델 로딩 완료. (소요 시간: {time.time() - start_time:.2f}초)")
    print("-" * 30)

    # 2. [신규] Scaler 로딩
    print(f"--- 2. Analyzer Scaler 로딩 ---")
    # core/analyzer.py에 정의된 SCALER_PATH('models/scaler.joblib')를 찾습니다.
    scaler = load_scaler() 
    if scaler is None:
        print("[테스트 실패] models/scaler.joblib 로딩에 실패했습니다.")
        print("-> (확인) models/scaler.joblib 파일이 존재하는지 확인하세요.")
        return
    print("Scaler 로딩 성공.")
    print("-" * 30)


    # 3. [수정] Analyzer로 특징 추출 (CNN + LSTM)
    print(f"--- 3. Analyzer 특징 추출 시작 ---")
    print(f"대상 파일: {TEST_FILE_PATH}")
    start_time = time.time()
    # [수정] analyze_file 함수 호출 (scaler 객체 전달)
    # 이 함수가 {'cnn': Numpy, 'lstm': Numpy} 딕셔너리를 반환합니다.
    data_dict = analyze_file(TEST_FILE_PATH, scaler) 
    
    if data_dict is None:
        print("[테스트 실패] Analyzer가 특징 추출에 실패했습니다. (None 반환)")
        return
    print(f"특징 추출 성공. (키: {data_dict.keys()})")
    print(f"  -> CNN 데이터 Shape: {data_dict['cnn'].shape}")
    print(f"  -> LSTM 데이터 Shape: {data_dict['lstm'].shape}")
    print(f"특징 추출 소요 시간: {time.time() - start_time:.2f}초")
    print("-" * 30)


    # 4. [수정] Predictor로 앙상블 예측
    print(f"--- 4. Predictor 앙상블 예측 시작 ---")
    start_time = time.time()
    # [수정] predict_ensemble 함수 호출 (data_dict 전달)
    # 기본 가중치(cnn: 0.5, lstm: 0.5)로 예측합니다.
    score = predictor.predict_ensemble(data_dict) 
    
    # (팁) 가중치를 3:7로 테스트하고 싶다면?
    # weights = {'cnn': 0.3, 'lstm': 0.7}
    # score = predictor.predict_ensemble(data_dict, weights=weights)
    
    if score is None:
        print("[테스트 실패] Predictor가 예측에 실패했습니다. (None 반환)")
        return
    print(f"예측 소요 시간: {time.time() - start_time:.2f}초")
    print("-" * 30)


    # 5. 최종 결과 출력 (유지)
    print("\n========= [ 최종 테스트 성공 ] =========")
    print(f"  파일: {TEST_FILE_PATH}")
    print(f"  최종 앙상블 악성 확률: {score * 100:.2f} %")
    print("=======================================\n")

# 스크립트 실행
if __name__ == "__main__":
    run_test()