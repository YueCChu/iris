document.addEventListener('DOMContentLoaded', function() {
    const runSelectorElement = document.getElementById('run-selector');
    const flowListElement = document.getElementById('flow-list');
    const detailsViewElement = document.getElementById('details-view');
    const noSelectionElement = document.getElementById('no-selection');

    // Elements to populate
    const vulnTypeElement = document.getElementById('vuln-type');
    const vulnSeverityElement = document.getElementById('vuln-severity');
    const vulnPathSourceElement = document.getElementById('vuln-path-source');
    const vulnPathPropagationContainer = document.getElementById('vuln-path-propagation');
    const vulnPathSinkElement = document.getElementById('vuln-path-sink');
    const vulnRootCauseElement = document.getElementById('vuln-root-cause');
    const vulnFixSuggestionsElement = document.getElementById('vuln-fix-suggestions');
    const vulnFixDiffElement = document.getElementById('vuln-fix-diff');

    let manifestData = [];      // To store data from analysis_manifest.json
    let currentAnalysisRunData = []; // To store data for the selected run's JSON file

    // --- Load the manifest file first ---
    async function loadManifest() {
        try {
            // 此处假设 analysis_manifest.json 与 visualization.html 在同一目录
            // 如果不是，请调整路径
            const response = await fetch('analysis_manifest.json'); 
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            manifestData = await response.json();
            populateRunSelector(manifestData);
        } catch (error) {
            console.error("Error loading manifest data:", error);
            noSelectionElement.textContent = 'Failed to load analysis manifest. Run the generation script.';
            noSelectionElement.classList.remove('hidden');
            detailsViewElement.classList.add('hidden');
        }
    }

    // --- Populate the run selector dropdown ---
    function populateRunSelector(data) {
        if (!data || data.length === 0) {
            runSelectorElement.innerHTML = '<option value="">No analysis runs found</option>';
            return;
        }
        data.forEach((runEntry, index) => {
            const option = document.createElement('option');
            option.value = index; // Use index to easily retrieve from manifestData
            option.textContent = runEntry.display_name || `Run ${index + 1}`;
            runSelectorElement.appendChild(option);
        });

        runSelectorElement.addEventListener('change', handleRunSelection);
    }

    // --- Handle selection of a run from the dropdown ---
    async function handleRunSelection() {
        const selectedIndex = runSelectorElement.value;
        flowListElement.innerHTML = ''; // Clear previous flow list
        detailsViewElement.classList.add('hidden');
        noSelectionElement.textContent = 'Loading analysis data...';
        noSelectionElement.classList.remove('hidden');

        if (selectedIndex === "") {
            noSelectionElement.textContent = 'Select an analysis run and then a flow to view details.';
            return;
        }

        const selectedRunEntry = manifestData[parseInt(selectedIndex)];
        try {
            // Load the specific analysis JSON file for the selected run
            // selectedRunEntry.file_path 是相对于 manifest 文件的路径
            const response = await fetch(selectedRunEntry.file_path);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status} for ${selectedRunEntry.file_path}`);
            }
            currentAnalysisRunData = await response.json();
            populateFlowListForRun(currentAnalysisRunData);
            if (currentAnalysisRunData && currentAnalysisRunData.length > 0) {
                 noSelectionElement.textContent = 'Select a flow from the list above to view details.';
            } else {
                 noSelectionElement.textContent = 'No True Positive flows found in the selected run.';
            }
        } catch (error) {
            console.error(`Error loading detailed analysis for ${selectedRunEntry.display_name}:`, error);
            flowListElement.innerHTML = '<li>Error loading flow data.</li>';
            noSelectionElement.textContent = `Failed to load data for ${selectedRunEntry.display_name}.`;
        }
    }

    // --- Populate the sidebar flow list for the selected run ---
    function populateFlowListForRun(data) {
        flowListElement.innerHTML = ''; // Clear previous list
        if (!data || data.length === 0) {
            flowListElement.innerHTML = '<li>No TP flows in this run.</li>';
            return;
        }
        data.forEach((analysisItem, index) => {
            const listItem = document.createElement('li');
            const flowId = analysisItem.tp_flow_id || `Flow ${index + 1}`;
            // 使用 llm_detailed_analysis 内的 vulnerability_type_llm
            const vulnType = analysisItem.llm_detailed_analysis?.vulnerability_type_llm || 'Unknown Type';
            listItem.textContent = `ID: ${flowId} - ${vulnType.split('(')[0].trim()}`;
            listItem.dataset.index = index;
            listItem.addEventListener('click', () => {
                displayDetails(index);
                document.querySelectorAll('#flow-list li').forEach(li => li.classList.remove('active'));
                listItem.classList.add('active');
            });
            flowListElement.appendChild(listItem);
        });
    }

    // --- Display details of a selected flow ---
    function displayDetails(index) {
        const analysisItem = currentAnalysisRunData[index]; // Use data from the currently loaded run
        if (!analysisItem || !analysisItem.llm_detailed_analysis) {
            console.error("Selected analysis item or its llm_detailed_analysis is missing for index:", index);
            detailsViewElement.classList.add('hidden');
            noSelectionElement.textContent = 'Error: Could not load details for the selected flow.';
            noSelectionElement.classList.remove('hidden');
            return;
        }

        const details = analysisItem.llm_detailed_analysis;

        vulnTypeElement.textContent = details.vulnerability_type_llm || 'N/A';
        vulnSeverityElement.textContent = details.vulnerability_severity || 'N/A';

        vulnPathSourceElement.textContent = details.vulnerability_path?.source || 'N/A';
        
        vulnPathPropagationContainer.innerHTML = '';
        if (details.vulnerability_path?.propagation && details.vulnerability_path.propagation.length > 0) {
            details.vulnerability_path.propagation.forEach((step, i) => {
                const stepDiv = document.createElement('div');
                stepDiv.classList.add('propagation-step');
                const stepTitle = document.createElement('h5');
                stepTitle.textContent = `Propagation Step ${i + 1}`;
                const stepCode = document.createElement('pre');
                const codeElem = document.createElement('code');
                codeElem.className = 'language-java'; // Or auto-detect
                codeElem.textContent = step;
                stepCode.appendChild(codeElem);
                stepDiv.appendChild(stepTitle);
                stepDiv.appendChild(stepCode);
                vulnPathPropagationContainer.appendChild(stepDiv);
            });
        } else {
            vulnPathPropagationContainer.innerHTML = '<p>No propagation steps detailed.</p>';
        }

        vulnPathSinkElement.textContent = details.vulnerability_path?.sink || 'N/A';
        vulnRootCauseElement.textContent = details.root_cause_analysis || 'N/A';

        vulnFixSuggestionsElement.innerHTML = '';
        if (details.fix_suggestion_text && details.fix_suggestion_text.length > 0) {
            details.fix_suggestion_text.forEach(suggestion => {
                const li = document.createElement('li');
                li.textContent = suggestion;
                vulnFixSuggestionsElement.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = 'No fix suggestions provided.';
            vulnFixSuggestionsElement.appendChild(li);
        }

        vulnFixDiffElement.textContent = details.fix_example_diff || 'No diff example provided.';

        Prism.highlightAll(); // Re-run Prism for newly added content

        detailsViewElement.classList.remove('hidden');
        noSelectionElement.classList.add('hidden');
    }

    // --- Initial Load ---
    loadManifest();
});