import os
from openai import OpenAI
import models.config as config
from utils.mylogger import MyLogger
from models.llm import LLM

_api_model_name_map = {
    "deepseek-v3": "ep-20250513152531-m64dp",
    "deepseek-r1": "ep-20250422195622-zgqwm",
}

class DeepSeekModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        # 这里传入 _api_model_name_map
        super().__init__(model_name, logger, _api_model_name_map, **kwargs)
        self.api_key = "34237fbd-8bfd-4efb-9dd8-18623c4cacfb"
        self.base_url = "https://ark.cn-beijing.volces.com/api/v3"
        self.model = _api_model_name_map[model_name]  # 直接传入推理接入点ID
        self.client = OpenAI(base_url=self.base_url, api_key=self.api_key)
        self.logger = logger

    def predict(self, main_prompt, batch_size=0, no_progress_bar=False, stream=False):
        """
        main_prompt: 
            - 若为单条，格式为 [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]
            - 若为批量，格式为 List[List[{"role":..., "content":...}]]
        """
        self.logger.info(f"DeepSeekModel predict: received prompt")
        # self.logger.info(f"DeepSeekModel predict: received prompt: {main_prompt}")
        def format_prompt(prompt):
            # 保证prompt为list且每项有role和content
            return [{"role": p.get("role", "user"), "content": p["content"]} for p in prompt]

        if batch_size > 0 and isinstance(main_prompt, list) and isinstance(main_prompt[0], list):
            # 批量推理
            results = []
            for prompt in main_prompt:
                messages = format_prompt(prompt)
                completion = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                )
                results.append(completion.choices[0].message.content)
                self.logger.info(f"DeepSeekModel predict: received response")
            return results
        else:
            # 单条推理
            messages = format_prompt(main_prompt)
            if stream:
                stream_resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    stream=True,
                )
                output = ""
                for chunk in stream_resp:
                    if not chunk.choices:
                        continue
                    content = chunk.choices[0].delta.content
                    if content:
                        print(content, end="", flush=True)
                        output += content
                print()
                return output
            else:
                completion = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                )
                self.logger.info(f"DeepSeekModel predict: received response")
                return completion.choices[0].message.content
