import os
import sys
import subprocess as sp
import pandas as pd
import shutil
import json
import re
import argparse
import numpy as np
import copy
import math
import random
from tqdm import tqdm

from src.prompts import SNIPPET_CONTEXT_SIZE, POSTHOC_FILTER_HINTS # POSTHOC_FILTER_HINTS 可能也需要
from src.queries import QUERIES

class EvaluationPipeline:
    def __init__(
            self,
            project_fixed_methods,
            class_locs_path,
            func_locs_path,
            project_source_code_dir,
            external_apis_csv_path = None,
            candidate_apis_csv_path = None,
            llm_labelled_sink_apis_path = None,
            llm_labelled_source_apis_path = None,
            llm_labelled_taint_prop_apis_path = None,
            source_func_param_candidates_path = None,
            llm_labelled_source_func_params_path = None,
            query_output_result_sarif_path = None,
            posthoc_filtering_output_result_sarif_path = None,
            final_output_json_path = None,
            project_logger = None,
            overwrite = False,
            test_run = False,
            # Add a parameter to control code flow output for TPs
            output_tp_codeflow=False, # New parameter
            tp_codeflow_output_file=None # Optional: file to save TP codeflows
    ):
        self.project_fixed_methods = project_fixed_methods
        self.class_locs_path = class_locs_path
        self.func_locs_path = func_locs_path
        self.project_source_code_dir = project_source_code_dir
        self.external_apis_csv_path = external_apis_csv_path
        self.candidate_apis_csv_path = candidate_apis_csv_path
        self.llm_labelled_sink_apis_path = llm_labelled_sink_apis_path
        self.llm_labelled_source_apis_path = llm_labelled_source_apis_path
        self.llm_labelled_taint_prop_apis_path = llm_labelled_taint_prop_apis_path
        self.source_func_param_candidates_path = source_func_param_candidates_path
        self.llm_labelled_source_func_params_path = llm_labelled_source_func_params_path
        self.query_output_result_sarif_path = query_output_result_sarif_path
        self.posthoc_filtering_output_result_sarif_path = posthoc_filtering_output_result_sarif_path
        self.final_output_json_path = final_output_json_path
        self.project_logger = project_logger
        self.overwrite = overwrite,
        self.test_run = test_run
        self.output_tp_codeflow = output_tp_codeflow # Store the new parameter
        self.tp_codeflow_output_file = tp_codeflow_output_file
        self.query_name = "unknown_query" # 初始化一个默认值

        # 加载类和函数位置信息，并转换为字典格式
        self.enclosing_class_locs = {}
        if os.path.exists(self.class_locs_path):
            _project_classes_csv = pd.read_csv(self.class_locs_path)
            self.enclosing_class_locs = self._extract_enclosing_decl_locs_map_internal(_project_classes_csv)
        elif self.project_logger:
            self.project_logger.error(f"Class location file not found: {self.class_locs_path}")

        self.enclosing_func_locs = {}
        if os.path.exists(self.func_locs_path):
            _project_methods_csv = pd.read_csv(self.func_locs_path)
            self.enclosing_func_locs = self._extract_enclosing_decl_locs_map_internal(_project_methods_csv)
        elif self.project_logger:
            self.project_logger.error(f"Function location file not found: {self.func_locs_path}")

    # --- 本地实现的辅助函数 (改编自 ContextualAnalysisPipeline) ---

    def _extract_enclosing_decl_locs_map_internal(self, decl_locs_df):
        # (与之前建议中的实现相同)
        enclosing_decl_locs = {}
        for _, row in decl_locs_df.iterrows():
            if row["file"] not in enclosing_decl_locs:
                enclosing_decl_locs[row["file"]] = []
            enclosing_decl_locs[row["file"]].append((row["name"], row["start_line"], row["end_line"]))
        return enclosing_decl_locs

    def _find_enclosing_declaration_internal(self, start_line, end_line, decl_locs_for_file):
        # (与 ContextualAnalysisPipeline.find_enclosing_declaration 逻辑相同，但不依赖self)
        closest_start_end = None
        for decl_loc in decl_locs_for_file: # decl_locs_for_file 是特定文件的 decl list
            if decl_loc[1] <= start_line and end_line <= decl_loc[2]:
                if closest_start_end is None:
                    closest_start_end = decl_loc
                else:
                    if decl_loc[1] > closest_start_end[1]: # 更近的（更大的起始行）
                        closest_start_end = decl_loc
        return closest_start_end

    def _get_snippet_from_loc_internal(self, loc, kind):
        # 改编自 ContextualAnalysisPipeline.get_snippet_from_loc
        # 使用 self.project_source_code_dir, self.enclosing_class_locs, self.enclosing_func_locs
        # 和 self._find_enclosing_declaration_internal

        file_url_key = loc.get("file_url")
        if not file_url_key:
            if self.project_logger: self.project_logger.error("Missing file_url in loc")
            return "Error: Missing file_url in loc", (None, None, None)

        file_dir = os.path.join(self.project_source_code_dir, file_url_key)
        if not os.path.exists(file_dir):
            if self.project_logger: self.project_logger.warning(f"Source file not found: {file_dir}")
            return f"Error: Source file not found {file_url_key}", (None, None, None)

        try:
            with open(file_dir, 'r', encoding='utf-8') as f:
                file_lines = f.readlines() # Read all lines at once
        except Exception as e:
            if self.project_logger: self.project_logger.error(f"Error reading file {file_dir}: {e}")
            return f"Error: Failed to read file {file_url_key}", (None, None, None)

        start_line, end_line = loc.get('start_line'), loc.get('end_line', loc.get('start_line'))
        if start_line is None:
            if self.project_logger: self.project_logger.error("Missing start_line in loc")
            return "Error: Missing start_line in loc", (None, None, None)


        class_decl_str, func_decl_str = None, None
        boundary = (0, len(file_lines))

        # 获取外层类
        if file_url_key in self.enclosing_class_locs:
            class_start_end = self._find_enclosing_declaration_internal(start_line, end_line, self.enclosing_class_locs[file_url_key])
            if class_start_end:
                class_decl_line_index = class_start_end[1] - 1
                if 0 <= class_decl_line_index < len(file_lines):
                    class_decl_str = file_lines[class_decl_line_index].strip()
                    if class_decl_str and not class_decl_str.endswith("{"):
                        class_decl_str += " {"
                boundary = (class_start_end[1], class_start_end[2])


        # 获取外层函数
        if file_url_key in self.enclosing_func_locs:
            func_start_end = self._find_enclosing_declaration_internal(start_line, end_line, self.enclosing_func_locs[file_url_key])
            if func_start_end:
                func_decl_line_index = func_start_end[1] - 1
                if 0 <= func_decl_line_index < len(file_lines):
                    func_decl_str = file_lines[func_decl_line_index].strip()
                    if func_decl_str and not func_decl_str.endswith("{"):
                        func_decl_str += " {"
                # 函数边界通常比类边界更精确
                boundary = (func_start_end[1], func_start_end[2])


        # 计算代码片段的起止行
        # SNIPPET_CONTEXT_SIZE 需要从 prompts.py 导入
        snippet_start_line_num = max(start_line - 1 - SNIPPET_CONTEXT_SIZE, boundary[0] -1) # 0-indexed
        start_ellipses = "...\n" if snippet_start_line_num > (boundary[0] -1) else ""
        
        snippet_end_line_num = min(end_line -1 + SNIPPET_CONTEXT_SIZE, boundary[1] - 1) # 0-indexed
        end_ellipses = "    ..." if snippet_end_line_num < (boundary[1] - 2) else ""

        snippet_parts = []
        base_snippet_parts = []

        for i in range(snippet_start_line_num, snippet_end_line_num + 1):
            if 0 <= i < len(file_lines):
                line_content = file_lines[i]
                # 标记源/汇所在行
                if (start_line - 1) <= i < end_line : # Handle multi-line regions
                    snippet_parts.append(line_content.rstrip('\n') + f" // <---- This is {kind.upper()}\n")
                    base_snippet_parts.append(line_content.rstrip('\n'))
                elif line_content.strip() != "":
                    snippet_parts.append(line_content)
                    base_snippet_parts.append(line_content)
        
        snippet = "".join(snippet_parts)
        base_snippet = "\n".join(base_snippet_parts)


        full_snippet_parts = []
        if class_decl_str:
            full_snippet_parts.append(class_decl_str + "\n")
        if func_decl_str:
            full_snippet_parts.append(("  " if class_decl_str else "") + func_decl_str + "\n")
        
        indent = "    " if func_decl_str else ("  " if class_decl_str else "")
        full_snippet_parts.append(indent + start_ellipses)
        full_snippet_parts.append(indent + snippet.replace("\n", "\n" + indent).rstrip(indent)) # Indent snippet
        full_snippet_parts.append("\n" + indent + end_ellipses if end_ellipses else "")

        if func_decl_str:
            full_snippet_parts.append("\n" + ("  " if class_decl_str else "") + "}")
        if class_decl_str:
            full_snippet_parts.append("\n}")
            
        snippet_with_decl = "".join(full_snippet_parts)

        return snippet_with_decl, (base_snippet, func_decl_str, class_decl_str)

    def _intermediate_step_prompt_internal(self, i, loc):
        # 改编自 ContextualAnalysisPipeline.intermediate_step_prompt
        file_url_key = loc.get("file_url")
        if not file_url_key: return None
        
        file_name = os.path.basename(file_url_key)
        file_dir = os.path.join(self.project_source_code_dir, file_url_key)

        if not os.path.exists(file_dir): return None
        try:
            with open(file_dir, 'r', encoding='utf-8') as f:
                file_lines = f.readlines()
        except Exception:
            return None

        line_num = loc.get('start_line')
        if line_num is None or not (0 < line_num <= len(file_lines)):
            return None
        
        line_content = file_lines[line_num - 1].strip()

        func_name_str = ""
        if file_url_key in self.enclosing_func_locs:
            enclosing_func = self._find_enclosing_declaration_internal(line_num, line_num, self.enclosing_func_locs[file_url_key])
            if enclosing_func:
                func_name_str = f":{enclosing_func[0]}"
        
        return f"- Step {i + 1} [{file_name}{func_name_str} L{line_num}]: {line_content}"

    def _intermediate_steps_prompt_internal(self, path_locs):
        # 改编自 ContextualAnalysisPipeline.intermediate_steps_prompt
        # 省略了步长调整逻辑，直接展示所有中间步骤，或按需添加步长逻辑
        step_size = max(1, len(path_locs) // 10 if len(path_locs) > 12 else 1) # 类似原逻辑
        trimmed_path_locs = path_locs[1:-1:step_size] # 应用步长

        result_parts = []
        for i, loc in enumerate(trimmed_path_locs):
            prompt_line = self._intermediate_step_prompt_internal(i, loc) # 调用本地版本
            if prompt_line:
                result_parts.append(prompt_line)
        return "\n".join(result_parts)

    def _format_tp_codeflow_text(self, path_locs, query_name):
        # Use the local helper functions defined above
        if not path_locs:
            return "Error: Path locations of the code flow are empty."

        source_loc = path_locs[0]
        sink_loc = path_locs[-1]

        source_snippet_text, _ = self._get_snippet_from_loc_internal(source_loc, "SOURCE")
        sink_snippet_text, _ = self._get_snippet_from_loc_internal(sink_loc, "SINK")
        
        intermediate_steps_text = self._intermediate_steps_prompt_internal(path_locs)

        query_obj = QUERIES.get(query_name, {})
        cwe_id_from_query = query_obj.get("cwe_id", "Unknown CWE_ID")
        cwe_desc = query_obj.get("desc", "Unknown vulnerability type")
        # hint = POSTHOC_FILTER_HINTS.get(cwe_id_from_query, "") # Uncomment if needed and ensure POSTHOC_FILTER_HINTS is imported

        formatted_text = (
            f"--- True Positive Code Flow ---\n"
            f"Query Name: {query_name}\n"
            f"Vulnerability Type: {cwe_desc} (CWE-{cwe_id_from_query})\n\n"
            # f"Hint: {hint}\n\n" # Uncomment if needed
            f"Source Info:\n{source_loc.get('message','N/A')}\nCode Snippet:\n{source_snippet_text}\n\n"
            f"Intermediate Steps:\n{intermediate_steps_text}\n\n"
            f"Sink Info:\n{sink_loc.get('message','N/A')}\nCode Snippet:\n{sink_snippet_text}\n"
            f"--- End of Code Flow ---\n"
        )
        return formatted_text

    # _convert_sarif_flow_to_path_locations 方法与上一轮建议中的实现相同
    def _convert_sarif_flow_to_path_locations(self, code_flow_sarif):
        path_locations = []
        if "threadFlows" not in code_flow_sarif or not code_flow_sarif["threadFlows"]:
            if self.project_logger: self.project_logger.error("Missing threadFlows in SARIF code_flow")
            return path_locations
            
        thread_flow = code_flow_sarif["threadFlows"][0]
        locations = thread_flow.get("locations", [])
        for loc_sarif in locations:
            try:
                if "location" not in loc_sarif or "physicalLocation" not in loc_sarif["location"]: continue
                physical_loc = loc_sarif["location"]["physicalLocation"]
                if "artifactLocation" not in physical_loc or "uri" not in physical_loc["artifactLocation"]: continue
                file_url = physical_loc["artifactLocation"]["uri"]
                if "region" not in physical_loc or "startLine" not in physical_loc["region"]: continue
                region = physical_loc["region"]
                start_line = region["startLine"]
                start_column = region.get("startColumn", 0)
                end_line = region.get("endLine", start_line)
                end_column = region.get("endColumn")
                message = "N/A"
                if "message" in loc_sarif["location"] and "text" in loc_sarif["location"]["message"]:
                    message = loc_sarif["location"]["message"]["text"]
                path_locations.append({
                    "file_url": file_url, "start_line": start_line, "start_column": start_column,
                    "end_line": end_line, "end_column": end_column, "message": message
                })
            except KeyError as e:
                if self.project_logger: self.project_logger.error(f"从SARIF提取位置时发生KeyError: {e} 在 {loc_sarif}")
                continue
            except Exception as e:
                if self.project_logger: self.project_logger.error(f"从SARIF提取位置时发生错误: {e}")
                continue
        return path_locations

    def get_source_line(self, location):
        relative_file_url = location["location"]["physicalLocation"]["artifactLocation"]["uri"]
        line_num = location["location"]["physicalLocation"]["region"]["startLine"]
        file_dir = f"{self.project_source_code_dir}/{relative_file_url}"
        if not os.path.exists(file_dir):
            print("Not found ", file_dir)
            return ""
        else:
            file_lines = list(open(file_dir, 'r').readlines())
            if line_num > len(file_lines):
                return ""
            else:
                line = file_lines[line_num - 1]
                return line

    def compute_statistics(self):
        if self.test_run:
            num_external_api_calls = 0
            num_api_candidates = 0
            num_labelled_sinks = 0
            num_labelled_sources = 0
            num_labelled_taint_props = 0
            num_func_param_candidates = 0
            num_labelled_func_param_sources = 0
        else:
            num_external_api_calls = len(pd.read_csv(self.external_apis_csv_path))
            num_api_candidates = len(pd.read_csv(self.candidate_apis_csv_path))
            num_labelled_sinks = len(json.load(open(self.llm_labelled_sink_apis_path)))
            num_labelled_sources = len(json.load(open(self.llm_labelled_source_apis_path)))
            num_labelled_taint_props = len(json.load(open(self.llm_labelled_taint_prop_apis_path)))
            num_func_param_candidates = len(pd.read_csv(self.source_func_param_candidates_path))
            num_labelled_func_param_sources = len(json.load(open(self.llm_labelled_source_func_params_path)))

        return {
            "num_external_api_calls": num_external_api_calls,
            "num_api_candidates": num_api_candidates,
            "num_labelled_sources": num_labelled_sources,
            "num_labelled_taint_propagators": num_labelled_taint_props,
            "num_labelled_sinks": num_labelled_sinks,
            "num_public_func_candidates": num_func_param_candidates,
            "num_labelled_func_param_sources": num_labelled_func_param_sources,
            "num_gpt_calls_for_posthoc_filtering": 0,
            "num_cached_during_posthoc_filtering": 0,
        }

    def extract_code_flow_passing_files(self, code_flow):
        thread_flow = code_flow["threadFlows"][0]
        locations = thread_flow["locations"]
        for loc in locations:
            file_name = loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
            yield file_name

    def extract_code_flow_passing_methods(self, project_classes, project_methods, code_flow):
        thread_flow = code_flow["threadFlows"][0]
        locations = thread_flow["locations"]
        for loc in locations:
            try:
                file_name = loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
                region = loc["location"]["physicalLocation"]["region"]
                start_line = region["startLine"]

                # Get the closest enclosing class
                relevant_classes = project_classes[
                    (project_classes["file"] == file_name) &
                    (project_classes["start_line"] <= start_line) &
                    (project_classes["end_line"] >= start_line)
                ].sort_values(by="start_line", ascending=False)
                if len(relevant_classes) == 0: continue
                relevant_class = relevant_classes.iloc[0]["name"]

                # Get the closest enclosing method
                relevant_methods = project_methods[
                    (project_methods["file"] == file_name) &
                    (project_methods["start_line"] <= start_line) &
                    (project_methods["end_line"] >= start_line)
                ].sort_values(by="start_line", ascending=False)
                if len(relevant_methods) == 0: continue
                relevant_method = relevant_methods.iloc[0]["name"]
            except Exception as e:
                continue
            # Yield
            yield f"{file_name}:{relevant_class}:{relevant_method}"

    def iter_code_flows(self, sarif_json):
        """
        Iterate through the code flows within a SARIF json obtained from running path queries with CodeQL
        """
        for (i, result) in enumerate(sarif_json["runs"][0]["results"]):
            if "codeFlows" not in result: continue
            code_flows = result["codeFlows"]
            for (j, code_flow) in enumerate(code_flows):
                yield (i, j, code_flow)

    def ignore_code_flow(self, code_flow):
        thread_flow = code_flow["threadFlows"][0]
        locations = thread_flow["locations"]
        first_location = locations[0]
        last_location = locations[-1]

        # {
        #   'location': {
        #     'physicalLocation': {
        #       'artifactLocation': {
        #         'uri': 'dspace-api/src/main/java/org/dspace/administer/CommunityFiliator.java',
        #         'uriBaseId': '%SRCROOT%',
        #         'index': 0
        #       },
        #       'region': {
        #         'startLine': 81,
        #         'startColumn': 24,
        #         'endColumn': 48
        #       }
        #     },
        #     'message': {
        #       'text': 'getOptionValue(...) : String'
        #     }
        #   }
        # }

        def is_println(loc):
            # line = self.get_source_line(loc)
            # if ".println(" in line or ".print(" in line: return True
            return False

        def ignore_location(loc):
            if "toString" in loc['location']['message']['text']: return True
            if "println" in loc['location']['message']['text']: return True
            # if "... + ..." in loc['location']['message']['text']: return True
            # if "next(" in loc['location']['message']['text']: return True
            # if "getOptionValue(" in loc['location']['message']['text']: return True
            # if "get(" in loc['location']['message']['text']: return True
            # if "getProperty(" in loc['location']['message']['text']: return True
            return False

        ignore = is_println(last_location)
        if not ignore: ignore = ignore or ignore_location(first_location)
        if not ignore: ignore = ignore or ignore_location(last_location)
        return ignore

    def evaluate_sarif_result(self, sarif_path):
        # (方法开始部分与上一轮建议相同：加载SARIF，加载类/方法位置，提取fixed_methods等)
        if self.test_run: return {}

        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                result_sarif = json.load(f)
        except FileNotFoundError:
            if self.project_logger: self.project_logger.error(f"SARIF file not found: {sarif_path}")
            return {}
        except json.JSONDecodeError:
            if self.project_logger: self.project_logger.error(f"Failed to decode SARIF file: {sarif_path}")
            return {}

        project_classes_df = pd.read_csv(self.class_locs_path) if os.path.exists(self.class_locs_path) else pd.DataFrame()
        project_methods_df = pd.read_csv(self.func_locs_path) if os.path.exists(self.func_locs_path) else pd.DataFrame()

        fixed_files, fixed_methods_set = set(), set()
        if not self.project_fixed_methods.empty: # 检查DataFrame是否为空
            for _, row in self.project_fixed_methods.iterrows():
                file_name, class_name, method_name = row["file"], row["class"], row["method"]
                if "src/test" in file_name: continue
                fixed_files.add(file_name)
                fixed_methods_set.add(f"{file_name}:{class_name}:{method_name}")

        num_true_pos_paths_file, num_true_pos_paths_method = 0, 0
        tp_result_file_ids, tp_result_method_ids = set(), set()
        num_total_valid_flows = 0
        code_flow_passes_fix_file, code_flow_passes_fix_method = False, False
        
        tp_codeflows_entries = []  # Store dicts with alert_id, tp_type, formatted_flow

        all_code_flows_sarif = list(self.iter_code_flows(result_sarif))
        code_flow_iterator = tqdm(all_code_flows_sarif, desc="Evaluating code flows in SARIF results", disable=not all_code_flows_sarif)

        for (result_id, _, code_flow_sarif_data) in code_flow_iterator:
            if self.ignore_code_flow(code_flow_sarif_data):
                continue

            num_total_valid_flows += 1
            current_path_locations = self._convert_sarif_flow_to_path_locations(code_flow_sarif_data)
            if not current_path_locations:
                continue

            passing_files = set(self.extract_code_flow_passing_files(code_flow_sarif_data))
            is_tp_file = len(fixed_files.intersection(passing_files)) > 0

            passing_methods = set(self.extract_code_flow_passing_methods(project_classes_df, project_methods_df, code_flow_sarif_data))
            is_tp_method = len(fixed_methods_set.intersection(passing_methods)) > 0

            if is_tp_file:
                code_flow_passes_fix_file = True
                num_true_pos_paths_file += 1
                tp_result_file_ids.add(result_id)

            if is_tp_method:
                code_flow_passes_fix_method = True
                num_true_pos_paths_method += 1
                tp_result_method_ids.add(result_id)

            if (is_tp_file or is_tp_method) and self.output_tp_codeflow:
                formatted_flow = self._format_tp_codeflow_text(current_path_locations, self.query_name)
                # Avoid duplicates
                unique = True
                for entry in tp_codeflows_entries:
                    if entry['formatted_flow'] == formatted_flow:
                        unique = False
                        break
                if unique:
                    log_prefix = "file"
                    if is_tp_file and is_tp_method:
                        log_prefix = "file and method"
                    elif is_tp_method:
                        log_prefix = "method"
                    tp_codeflows_entries.append({
                        "alert_id": result_id,
                        "tp_type": log_prefix,
                        "formatted_flow": formatted_flow
                    })

        # Save all TP code flows to file in the required format, skip terminal output
        if self.output_tp_codeflow and self.tp_codeflow_output_file and tp_codeflows_entries:
            try:
                mode = 'w' if self.overwrite else 'a'
                if mode == 'a' and not os.path.exists(self.tp_codeflow_output_file):
                    mode = 'w'
                with open(self.tp_codeflow_output_file, mode, encoding='utf-8') as f:
                    for entry in tp_codeflows_entries:
                        f.write(f"TP ({entry['tp_type']}) code flow (alert ID: {entry['alert_id']}):\n")
                        f.write(entry['formatted_flow'])
                        if not entry['formatted_flow'].endswith("\n"):
                            f.write("\n")
                        f.write("\n")
                self.project_logger.info(f"TP code flows saved to {self.tp_codeflow_output_file}")
            except Exception as e:
                if self.project_logger:
                    self.project_logger.error(f"Failed to save TP code flows to {self.tp_codeflow_output_file}: {e}")
        
        num_true_pos_results_file = len(tp_result_file_ids)
        num_true_pos_results_method = len(tp_result_method_ids)

        return {
            "num_results": len(result_sarif.get("runs", [{}])[0].get("results", [])),
            "num_paths": num_total_valid_flows,
            "recall_file": code_flow_passes_fix_file,
            "num_tp_paths_file": num_true_pos_paths_file,
            "num_tp_results_file": num_true_pos_results_file,
            "recall_method": code_flow_passes_fix_method,
            "num_tp_paths_method": num_true_pos_paths_method,
            "num_tp_results_method": num_true_pos_results_method,
        }

    def run_vanilla_only(self):
        if os.path.exists(self.final_output_json_path) and not self.overwrite:
            result = json.load(open(self.final_output_json_path))
            if self.project_logger is not None:
                # self.project_logger.info(f"    ==> [Recall@File]   RESULT: {result['recall_file']}, #Paths: {result['num_paths']}, #TP: {result['num_tp_paths_file']}")
                self.project_logger.info(f"    ==> [Recall@Method] RESULT: {result['recall_method']}, #Paths: {result['num_paths']}, #TP: {result['num_tp_paths_method']}")
        elif os.path.exists(self.query_output_result_sarif_path):
            result = self.evaluate_sarif_result(self.query_output_result_sarif_path)
            if self.project_logger is not None:
                # self.project_logger.info(f"    ==> [Recall@File]   RESULT: {result['recall_file']}, #Paths: {result['num_paths']}, #TP: {result['num_tp_paths_file']}")
                self.project_logger.info(f"    ==> [Recall@Method] RESULT: {result['recall_method']}, #Paths: {result['num_paths']}, #TP: {result['num_tp_paths_method']}")
            json.dump(result, open(self.final_output_json_path, "w"))
        else:
            self.project_logger.info("    ==> Vanilla result file not found...")

    def run(self):
        need_eval = True
        if os.path.exists(self.final_output_json_path) and not self.overwrite:
            need_eval = False
            self.project_logger.info("  ==> Found existing statistics, loading...")
            result = json.load(open(self.final_output_json_path))
            if "vanilla_result" not in result:
                need_eval = True
            if "posthoc_filter_result" not in result:
                need_eval = True

        if need_eval:
            result = {}

            self.project_logger.info("  ==> Computing statistics...")
            result.update({ "statistics": self.compute_statistics() })

            self.project_logger.info("  ==> Evaluating results after stage 6 (vanilla)...")
            if os.path.exists(self.query_output_result_sarif_path):
                vanilla_result = self.evaluate_sarif_result(self.query_output_result_sarif_path)

                if self.project_logger is not None:
                    # self.project_logger.info(f"    ==> [Recall@File]   RESULT: {vanilla_result['recall_file']}, #Paths: {vanilla_result['num_paths']}, #TP Paths: {vanilla_result['num_tp_paths_file']}")
                    self.project_logger.info(f"    ==> [Recall@Method] RESULT: {vanilla_result['recall_method']}, #Paths: {vanilla_result['num_paths']}, #TP Paths: {vanilla_result['num_tp_paths_method']}")

                result.update({ "vanilla_result": vanilla_result })
            else:
                self.project_logger.info("    ==> Vanilla result file not found...")

            self.project_logger.info("  ==> Evaluating results after stage 7 (with posthoc-filtering)...")
            if os.path.exists(self.posthoc_filtering_output_result_sarif_path):
                posthoc_result = self.evaluate_sarif_result(self.posthoc_filtering_output_result_sarif_path)

                if self.project_logger is not None:
                    # self.project_logger.info(f"    ==> [Recall@File]   RESULT: {posthoc_result['recall_file']}, #Paths: {posthoc_result['num_paths']}, #TP Paths: {posthoc_result['num_tp_paths_file']}")
                    self.project_logger.info(f"    ==> [Recall@Method] RESULT: {posthoc_result['recall_method']}, #Paths: {posthoc_result['num_paths']}, #TP Paths: {posthoc_result['num_tp_paths_method']}")

                result.update({ "posthoc_filter_result": posthoc_result })
            else:
                self.project_logger.info("    ==> Posthoc filtering result file not found...")

            self.project_logger.info(f"  ==> Dumping final statistics and evaluation result to {'/'.join(self.final_output_json_path.split('/')[-4:])}...")
            json.dump(result, open(self.final_output_json_path, "w"))
        else:
            if "vanilla_result" in result:
                self.project_logger.info("  ==> Evaluating results after stage 6 (vanilla)...")
                # self.project_logger.info(f"    ==> [Recall@File]   RESULT: {result['vanilla_result']['recall_file']}, #Paths: {result['vanilla_result']['num_paths']}, #TP Paths: {result['vanilla_result']['num_tp_paths_file']}")
                self.project_logger.info(f"    ==> [Recall@Method] RESULT: {result['vanilla_result']['recall_method']}, #Paths: {result['vanilla_result']['num_paths']}, #TP Paths: {result['vanilla_result']['num_tp_paths_method']}")
            if "posthoc_filter_result" in result:
                self.project_logger.info("  ==> Evaluating results after stage 7 (with posthoc-filtering)...")
                # self.project_logger.info(f"    ==> [Recall@File]   RESULT: {result['posthoc_filter_result']['recall_file']}, #Paths: {result['posthoc_filter_result']['num_paths']}, #TP Paths: {result['posthoc_filter_result']['num_tp_paths_file']}")
                self.project_logger.info(f"    ==> [Recall@Method] RESULT: {result['posthoc_filter_result']['recall_method']}, #Paths: {result['posthoc_filter_result']['num_paths']}, #TP Paths: {result['posthoc_filter_result']['num_tp_paths_method']}")
