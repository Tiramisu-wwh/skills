#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Figma设计提取器
通过Figma MCP获取设计详情并提取测试相关信息
"""

import logging
from typing import Dict, List, Any, Optional
import json

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FigmaExtractor:
    """Figma设计信息提取器"""

    def __init__(self):
        self.figma_base_url = "https://www.figma.com"

    def extract_design_info(self, figma_url: str) -> Dict[str, Any]:
        """
        从Figma URL提取设计信息

        Args:
            figma_url: Figma设计链接

        Returns:
            Dict: 设计信息结构
        """
        try:
            # 提取文件key
            file_key = self._extract_file_key(figma_url)
            if not file_key:
                raise ValueError("无法从URL中提取Figma文件key")

            # TODO: 调用Figma MCP获取设计数据
            # 这里需要根据实际的Figma MCP接口进行调用
            design_data = self._call_figma_mcp(file_key)

            # 解析设计数据
            parsed_info = self._parse_design_data(design_data)

            logger.info(f"成功提取Figma设计信息: {file_key}")
            return parsed_info

        except Exception as e:
            logger.error(f"提取Figma设计信息失败: {e}")
            raise

    def _extract_file_key(self, figma_url: str) -> Optional[str]:
        """从Figma URL中提取文件key"""
        import re

        # 匹配Figma文件URL格式
        patterns = [
            r'figma\.com/file/([a-zA-Z0-9]+)',
            r'figma\.com/design/([a-zA-Z0-9]+)',
            r'figma\.com/proto/([a-zA-Z0-9]+)'
        ]

        for pattern in patterns:
            match = re.search(pattern, figma_url)
            if match:
                return match.group(1)

        return None

    def _call_figma_mcp(self, file_key: str) -> Dict[str, Any]:
        """
        调用Figma MCP获取设计数据

        Args:
            file_key: Figma文件key

        Returns:
            Dict: Figma设计数据
        """
        # TODO: 实现Figma MCP调用
        # 这里需要根据实际的Figma MCP接口进行调整
        logger.warning("Figma MCP调用功能待实现，返回模拟数据")

        # 模拟返回的设计数据结构
        mock_data = {
            'document': {
                'id': file_key,
                'name': '示例设计文件',
                'children': [
                    {
                        'id': 'page1',
                        'name': '登录页面',
                        'children': [
                            {
                                'id': 'frame1',
                                'name': '登录表单',
                                'type': 'FRAME',
                                'children': [
                                    {'id': 'input1', 'name': '用户名输入框', 'type': 'TEXT'},
                                    {'id': 'input2', 'name': '密码输入框', 'type': 'TEXT'},
                                    {'id': 'button1', 'name': '登录按钮', 'type': 'RECTANGLE'}
                                ]
                            }
                        ]
                    }
                ]
            }
        }

        return mock_data

    def _parse_design_data(self, design_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        解析Figma设计数据，提取测试相关信息

        Args:
            design_data: Figma原始设计数据

        Returns:
            Dict: 解析后的设计信息
        """
        parsed_info = {
            'type': 'figma',
            'title': '',
            'screens': [],
            'components': [],
            'interactions': [],
            'requirements': []
        }

        try:
            document = design_data.get('document', {})
            parsed_info['title'] = document.get('name', '未命名设计')

            # 解析页面/屏幕
            pages = document.get('children', [])
            for page in pages:
                screen_info = self._parse_page(page)
                parsed_info['screens'].append(screen_info)

            # 从设计元素中提取组件信息
            all_components = self._extract_components(design_data)
            parsed_info['components'] = all_components

            # 从设计规范中推导需求信息
            design_requirements = self._derive_requirements_from_design(design_data)
            parsed_info['requirements'].extend(design_requirements)

        except Exception as e:
            logger.error(f"解析设计数据失败: {e}")

        return parsed_info

    def _parse_page(self, page: Dict[str, Any]) -> Dict[str, Any]:
        """解析页面信息"""
        page_info = {
            'id': page.get('id', ''),
            'name': page.get('name', ''),
            'elements': [],
            'interactions': []
        }

        # 解析页面中的元素
        children = page.get('children', [])
        for child in children:
            element_info = self._parse_element(child)
            if element_info:
                page_info['elements'].append(element_info)

        return page_info

    def _parse_element(self, element: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """解析设计元素"""
        if not element:
            return None

        element_info = {
            'id': element.get('id', ''),
            'name': element.get('name', ''),
            'type': element.get('type', ''),
            'visible': element.get('visible', True),
            'properties': {}
        }

        # 根据元素类型提取特定属性
        element_type = element.get('type', '').lower()

        if element_type == 'text':
            element_info['properties']['text'] = element.get('characters', '')
            element_info['properties']['font_size'] = element.get('style', {}).get('fontSize', 0)

        elif element_type in ('rectangle', 'frame', 'component'):
            element_info['properties']['size'] = {
                'width': element.get('absoluteBoundingBox', {}).get('width', 0),
                'height': element.get('absoluteBoundingBox', {}).get('height', 0)
            }

            # 提取颜色信息
            fills = element.get('fills', [])
            if fills:
                element_info['properties']['color'] = fills[0].get('color', {})

        return element_info

    def _extract_components(self, design_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取设计组件信息"""
        components = []

        def traverse_node(node):
            if not isinstance(node, dict):
                return

            # 检查是否是组件
            if node.get('type') in ('COMPONENT', 'COMPONENT_SET'):
                component_info = {
                    'id': node.get('id', ''),
                    'name': node.get('name', ''),
                    'type': node.get('type', ''),
                    'description': node.get('description', '')
                }
                components.append(component_info)

            # 递归遍历子节点
            children = node.get('children', [])
            for child in children:
                traverse_node(child)

        # 从文档根节点开始遍历
        document = design_data.get('document', {})
        traverse_node(document)

        return components

    def _derive_requirements_from_design(self, design_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从设计规范推导需求信息"""
        requirements = []

        # 基于页面结构推导功能需求
        document = design_data.get('document', {})
        pages = document.get('children', [])

        for page in pages:
            page_name = page.get('name', '')
            elements = page.get('children', [])

            # 检查是否有表单元素（登录、注册等功能）
            has_form = any('表单' in elem.get('name', '') or
                          'form' in elem.get('name', '').lower()
                          for elem in elements)

            if has_form and ('登录' in page_name or 'login' in page_name.lower()):
                requirements.append({
                    'text': '系统应该支持用户登录功能',
                    'type': 'functional',
                    'source': f'Figma设计页面: {page_name}'
                })

            # 检查是否有搜索相关元素
            has_search = any('搜索' in elem.get('name', '') or
                           'search' in elem.get('name', '').lower()
                           for elem in elements)

            if has_search:
                requirements.append({
                    'text': '系统应该支持内容搜索功能',
                    'type': 'functional',
                    'source': f'Figma设计页面: {page_name}'
                })

            # 检查是否有列表或表格元素
            has_list = any('列表' in elem.get('name', '') or
                         'list' in elem.get('name', '').lower() or
                         'table' in elem.get('name', '').lower()
                         for elem in elements)

            if has_list:
                requirements.append({
                    'text': '系统应该支持数据列表展示功能',
                    'type': 'functional',
                    'source': f'Figma设计页面: {page_name}'
                })

        return requirements

    def generate_test_suggestions(self, design_info: Dict[str, Any]) -> List[str]:
        """
        基于设计信息生成测试建议

        Args:
            design_info: 解析后的设计信息

        Returns:
            List[str]: 测试建议列表
        """
        suggestions = []

        # 基于屏幕信息生成测试建议
        screens = design_info.get('screens', [])
        for screen in screens:
            screen_name = screen.get('name', '')
            elements = screen.get('elements', [])

            suggestions.append(f"需要对'{screen_name}'页面进行功能测试")

            # 检查交互元素
            interactive_elements = [elem for elem in elements
                                  if elem.get('type') in ('RECTANGLE', 'TEXT', 'COMPONENT')]
            if interactive_elements:
                suggestions.append(f"验证'{screen_name}'页面中{len(interactive_elements)}个交互元素的功能")

        # 基于组件信息生成测试建议
        components = design_info.get('components', [])
        if components:
            suggestions.append(f"对{len(components)}个设计组件进行一致性测试")

        # 基于推导的需求生成测试建议
        requirements = design_info.get('requirements', [])
        for req in requirements:
            req_text = req.get('text', '')
            suggestions.append(f"验证功能需求：{req_text}")

        return suggestions


if __name__ == "__main__":
    # 示例用法
    extractor = FigmaExtractor()

    # 测试URL解析
    test_url = "https://www.figma.com/file/abc123/Example-Design"
    file_key = extractor._extract_file_key(test_url)
    print(f"提取的文件key: {file_key}")

    # 测试设计数据解析
    if file_key:
        try:
            design_info = extractor.extract_design_info(test_url)
            print(f"设计信息标题: {design_info.get('title', '')}")
            print(f"屏幕数量: {len(design_info.get('screens', []))}")
            print(f"组件数量: {len(design_info.get('components', []))}")
            print(f"推导需求: {len(design_info.get('requirements', []))}")

            # 生成测试建议
            suggestions = extractor.generate_test_suggestions(design_info)
            print("测试建议:")
            for suggestion in suggestions:
                print(f"- {suggestion}")

        except Exception as e:
            print(f"测试失败: {e}")