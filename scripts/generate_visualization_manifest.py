# scripts/generate_visualization_manifest.py
import os
import json
import glob
import argparse #   添加 argparse 用于更灵活的路径配置

#   获取脚本所在的真实目录，用于构建相对路径
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
#   IRIS 项目根目录通常是脚本所在目录的上一级
#   如果脚本本身就在根目录，则 IRIS_ROOT_DIR = SCRIPT_DIR
#   我们假设脚本仍在 scripts/ 目录下，但可以从根目录运行
#   如果脚本被移动到根目录，那么 IRIS_ROOT_DIR = os.getcwd() (当从根目录运行时)
#   或者更健壮的方式是，让用户通过参数指定路径，或基于脚本位置计算

def find_analysis_files(output_base_dir):
    """
    Scans the output directory for LLM detailed analysis JSON files.
    """
    analysis_entries = []
    # 结构: output_base_dir/{project_name}/{run_id}/detailed_tp_analysis/llm_detailed_analysis_{project_name}_{query}.json
    
    search_pattern = os.path.join(output_base_dir, "*", "*", "detailed_tp_analysis", "llm_detailed_analysis_*.json")
    
    for filepath in glob.glob(search_pattern):
        try:
            # 使用 os.path.normpath 来规范化路径，消除多余的斜杠或点
            normalized_filepath = os.path.normpath(filepath)
            parts = normalized_filepath.split(os.sep)
            
            # 期望的结构:
            # ... / output_base_dir / project_name / run_id / detailed_tp_analysis / filename.json
            # 因此，parts[-1] 是文件名
            # parts[-2] 是 'detailed_tp_analysis'
            # parts[-3] 是 run_id
            # parts[-4] 是 project_name (从路径结构中获取)
            if len(parts) < 5: # 确保路径深度足够
                print(f"Skipping path with unexpected structure: {filepath}")
                continue

            filename = parts[-1]
            run_id = parts[-3]
            project_name_from_path = parts[-4]

            # 从文件名提取 project_name_in_file 和 query_name
            # 文件名格式: llm_detailed_analysis_{project_name_in_file}_{query}.json
            filename_stem = filename.replace("llm_detailed_analysis_", "").replace(".json", "")
            
            # 尝试更稳健地分割 project_name_in_file 和 query_name
            # 我们知道 project_name_from_path 可能包含下划线
            # 假设 project_name_in_file 与 project_name_from_path 相同
            project_name_in_file_parts = project_name_from_path.split('_')
            
            # 移除 project_name_from_path 对应的部分后，剩余的是 query
            if filename_stem.startswith(project_name_from_path):
                query_name_with_leading_underscore = filename_stem[len(project_name_from_path):]
                query_name = query_name_with_leading_underscore.lstrip('_') if query_name_with_leading_underscore else "unknown_query"
            else:
                # 如果文件名中的项目名与路径中的不完全匹配（可能由于历史命名），则尝试通用分割
                # 这是一个启发式方法，可能需要根据实际文件名调整
                temp_parts = filename_stem.split('_')
                query_name = temp_parts[-1] # 简单假设最后一个部分是query
                # project_name_in_file = "_".join(temp_parts[:-1]) # 其余部分是项目名
                # 这里我们仍然优先使用从路径中获取的 project_name_from_path

            if not query_name: # 进一步的 fallback
                query_name = "unknown_query"

            analysis_entries.append({
                "project_name": project_name_from_path,
                "run_id": run_id,
                "query_name": query_name,
                #   file_path 现在将是相对于 manifest_file 输出位置的相对路径
                #   这个计算将在 main 函数中进行，基于 manifest_file_path
                "raw_absolute_path": os.path.abspath(normalized_filepath), # 暂时存储绝对路径
                "display_name": f"{project_name_from_path} (Run: {run_id}, Query: {query_name})"
            })
        except IndexError:
            print(f"Could not parse path structure for: {filepath}")
        except Exception as e:
            print(f"Error processing file {filepath}: {e}")
            
    return analysis_entries

def main():
    parser = argparse.ArgumentParser(description="Generate a manifest file for IRIS LLM analysis results.")
    parser.add_argument(
        "--iris_root_dir",
        type=str,
        default=os.path.abspath(os.path.join(SCRIPT_DIR, "..")), # 默认为脚本所在目录的上一级
        help="The root directory of the IRIS project."
    )
    parser.add_argument(
        "--output_scan_dir",
        type=str,
        default=None, # 默认为 iris_root_dir / "output"
        help="The directory to scan for analysis results (typically 'output'). Defaults to 'iris_root_dir/output'."
    )
    parser.add_argument(
        "--manifest_output_dir",
        type=str,
        default=None, # 默认为 iris_root_dir / "visualization"
        help="The directory where 'analysis_manifest.json' will be saved. Defaults to 'iris_root_dir/visualization'."
    )
    args = parser.parse_args()

    iris_root_dir = os.path.abspath(args.iris_root_dir)
    output_scan_dir = args.output_scan_dir if args.output_scan_dir else os.path.join(iris_root_dir, "output")
    manifest_output_dir = args.manifest_output_dir if args.manifest_output_dir else os.path.join(iris_root_dir, "visualization")
    
    manifest_file_path = os.path.join(manifest_output_dir, "analysis_manifest.json")

    # OUTPUT_DIR = "../output" # 假设脚本在 scripts/ 目录下，output在上一级
    # MANIFEST_FILE = "../visualization/analysis_manifest.json"
    print(f"Scanning for analysis files in: {output_scan_dir}...")
    entries = find_analysis_files(output_scan_dir)
    
    # 确保 manifest 的输出目录存在
    os.makedirs(manifest_output_dir, exist_ok=True)

    # 更新 file_path 为相对于 manifest_file_path 目录的相对路径
    for entry in entries:
        entry["file_path"] = os.path.relpath(entry["raw_absolute_path"], manifest_output_dir).replace(os.sep, '/')
        del entry["raw_absolute_path"] # 移除临时的绝对路径

    with open(manifest_file_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2)
        
    print(f"Generated manifest with {len(entries)} entries at: {manifest_file_path}")
    if not entries:
        print("No analysis files found. Ensure your output directory structure and file naming conventions are correct.")
        print(f"Searched pattern: {os.path.join(output_scan_dir, '*', '*', 'detailed_tp_analysis', 'llm_detailed_analysis_*.json')}")

if __name__ == "__main__":
    main()
