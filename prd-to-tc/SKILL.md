---
name: prd-to-tc-generator
description: AI驱动的PRD测试用例生成器，使用Claude智能分析Word/PDF文档和Figma设计，创建结构化测试用例表格和自然语言描述的UI自动化测试用例。当Claude需要从PRD文档生成综合测试用例时使用：(1) 需求分析和测试规划，(2) 功能和UI测试用例创建，（3）测试分析报告
allowed-tools: [Read, Write, mcp__figma__get_figma_data, mcp__figma__download_figma_images]
---

# PRD测试用例生成器

## AI驱动的智能测试用例生成

当用户提供PRD文档路径时，我(Claude AI)将：

### 1. 智能解析PRD内容
- 使用脚本提取文档文本、表格和结构信息
- 深度理解业务需求和用户故事
- 识别功能模块、UI要求和业务流程

### 2. AI生成测试用例
- 为每个功能需求生成正向、异常、边界测试用例
- 创建具体的UI自动化测试步骤
- 提供可执行的测试数据和验证点

### 3. 格式化导出
- 生成Excel格式的标准测试用例表格
- 创建Markdown格式的UI自动化测试用例
- 提供完整的测试统计和分析报告

## 使用方法

### 输入格式
用户提供以下任一格式：
- Word文档路径 (.docx)
- PDF文档路径 (.pdf)
- Figma设计链接
- 直接粘贴PRD文本内容

### 处理流程

#### 阶段1：文档内容提取
我使用相应的方式提取原始内容：
- Word: `python scripts/content_extractor.py --word <文件路径>`
- PDF: `python scripts/content_extractor.py --pdf <文件路径>`
- Figma: **直接通过Figma MCP获取设计数据**，无需脚本中间层

#### 阶段2：AI智能分析
我基于提取的内容进行深度分析：

**需求分析**：
- 识别功能需求、非功能需求、约束条件
- 分析用户角色和使用场景
- 梳理业务流程和数据流转
- 理解UI设计和交互要求

**特殊处理：Figma设计分析**
当输入为Figma链接时：
1. **URL解析**：从Figma链接中提取file_key和可选的node_id
2. **MCP数据获取**：使用 `mcp__figma__get_figma_data` 获取结构化设计数据
3. **设计分析**：
   - 解析页面布局、组件层次、交互流程
   - 识别UI元素类型（按钮、输入框、文本、图片等）
   - 提取设计规范（颜色、字体、间距、尺寸）
   - 理解用户交互路径和业务流程
4. **图片资源获取**：如需要，使用 `mcp__figma__download_figma_images` 获取设计图片

**测试策略制定**：
- 确定测试范围和优先级
- 设计测试类型分布（功能/性能/安全/兼容性）
- 制定边界值和异常场景
- 规划测试数据和验证点

#### 阶段3：AI测试用例生成

**功能测试用例**：参考 `references/test_case_template.md`
- 正向测试：验证正常业务流程
- 异常测试：验证错误处理和边界条件
- 数据测试：验证数据完整性和准确性
- 集成测试：验证模块间交互

**UI自动化测试用例**：参考 `references/ui_prompt_engineering.md`
- 用自然语言描述的测试步骤
- 元素位置和交互描述
- 完整的验证断言和预期结果

#### 阶段4：结果导出

**创建输出文件的文件夹**：
- 在目录`/Users/wwh/Documents/R2ai/AI/AI智能平台/PRDtoTC`创建文件夹
**文件夹命名**：PRD名称/figma标题名称+YYYY-MM-DDTHH-mm-SS
- 后续生成的文件都保存至该文件夹内

**功能测试用例CSV导出要求**：
- cd至创建的文件夹内进行保存
**重要：生成CSV格式文件**
- **首先参考 `assets/基础用例模板.xlsx` 文件结构**，确保列名和格式完全一致

**模板参考步骤**：
1. 读取 `assets/基础用例模板.xlsx` 文件（如果存在）
2. 分析模板的列名结构和格式
3. 按照模板结构生成对应的CSV内容
4. 确保字段顺序和命名与模板完全一致

**标准字段结构**（严格遵循模板）
**文件命名**：测试用例_YYYY-MM-DDTHH-mm-SS.csv

**UI自动化用例导出要求**：
- cd至创建的文件夹内进行保存
- 使用Markdown格式，包含完整阶段3生成的UI自动化测试用例内容
**文件命名**：UI测试用例_YYYY-MM-DDTHH-mm-SS.md

**测试分析报告导出要求**：
- cd至创建的文件夹内进行保存
**文件命名**：测试分析报告_YYYY-MM-DDTHH-mm-SS.md

## 示例使用

### Word/PDF文档示例
```
用户: 请分析这个PRD文档生成测试用例：/path/to/prd.docx

我: 1. 正在提取文档内容...
   2. 完成需求分析，识别出15个功能需求
   3. 生成45个测试用例（含正向/异常/边界测试）
   4. 创建12个UI自动化测试用例
   5. 创建文件夹
   6. 导出Excel和Markdown格式结果

   结果文件：
   - test_cases_20241128.csv (45个测试用例)
   - ui_tests_20241128.md (12个UI测试用例)
```

### Figma设计链接示例
```
用户: 请分析这个Figma设计生成测试用例：https://www.figma.com/design/HYj43oecdPu8gyeH5BaAFl/ADME统计系统?node-id=130-8805

我: 1. 正在解析Figma链接...
   2. 获取设计数据：file_key=HYj43oecdPu8gyeH5BaAFl, node_id=130-8805
   3. 分析UI设计，识别出8个页面和25个交互组件
   4. 完成需求分析，推导出12个功能需求
   5. 生成36个测试用例（含UI交互测试、业务流程测试）
   6. 创建18个UI自动化测试用例（自然语言描述）
   7. 创建文件夹
   8. 导出Excel和Markdown格式结果

   结果文件：
   - test_cases_20241128.csv (36个测试用例)
   - ui_tests_20241128.md (18个UI测试用例)
   - test_analysis_report_20241128.md (测试分析报告)
```

## 依赖要求

运行辅助脚本需要：
```bash
pip install python-docx pandas openpyxl PyPDF2
```

## 直接使用方式

现在你可以直接对我说：

**Word/PDF文档**：
```
"请分析这个PRD文档生成测试用例：/path/to/document.docx"
```

**Figma设计链接**：
```
"请分析这个Figma设计生成测试用例：https://www.figma.com/design/xxx/项目名称?node-id=xxx"
```

**直接文本内容**：
```
"请分析以下PRD内容生成测试用例：[粘贴PRD文本内容]"
```

我将：
1. **智能识别输入类型**（文档/Figma链接/文本）
2. **自动提取内容**（脚本解析/MCP获取/直接分析）
3. **进行AI智能分析**（需求识别/测试策略制定）
4. **生成完整的测试用例**（功能测试/UI自动化）
5. **创建文件夹**
6. **导出结构化文件**（Excel CSV + Markdown）