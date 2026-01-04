---
layout: page
title: Tags
icon: fas fa-tags
order: 2
---

<style>
.tag-section {
  margin-bottom: 3rem;
}

.tag-section h2 {
  font-size: 1.5rem;
  margin-bottom: 1rem;
  padding-bottom: 0.5rem;
  border-bottom: 2px solid var(--btn-border-color);
}

.tag-cloud {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.tag-badge {
  display: inline-block;
  padding: 0.35rem 0.75rem;
  background: var(--tag-bg);
  border: 1px solid var(--tag-border-color);
  border-radius: 0.5rem;
  transition: all 0.2s ease;
  text-decoration: none;
}

.tag-badge:hover {
  background: var(--tag-hover);
  transform: translateY(-2px);
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.tag-count {
  opacity: 0.6;
  font-size: 0.85em;
}
</style>

{% assign all_tags = site.tags | sort %}

<!-- Areas of Interest -->
<div class="tag-section">
  <h2 id="areas">Areas of Interest</h2>
  <div class="tag-cloud">
    {% for tag_data in all_tags %}
      {% assign tag_name = tag_data[0] %}
      {% if site.data.tag_groups.areas contains tag_name %}
        <a href="{{ site.baseurl }}/tags/{{ tag_name | slugify }}/" class="tag-badge">
          {{ tag_name }} <span class="tag-count">({{ tag_data[1].size }})</span>
        </a>
      {% endif %}
    {% endfor %}
  </div>
</div>

<!-- Vulnerabilities -->
<div class="tag-section">
  <h2 id="vulnerabilities">Vulnerabilities</h2>
  <div class="tag-cloud">
    {% for tag_data in all_tags %}
      {% assign tag_name = tag_data[0] %}
      {% if site.data.tag_groups.vulnerabilities contains tag_name %}
        <a href="{{ site.baseurl }}/tags/{{ tag_name | slugify }}/" class="tag-badge">
          {{ tag_name }} <span class="tag-count">({{ tag_data[1].size }})</span>
        </a>
      {% endif %}
    {% endfor %}
  </div>
</div>

<!-- Languages -->
<div class="tag-section">
  <h2 id="languages">Languages</h2>
  <div class="tag-cloud">
    {% for tag_data in all_tags %}
      {% assign tag_name = tag_data[0] %}
      {% if site.data.tag_groups.languages contains tag_name %}
        <a href="{{ site.baseurl }}/tags/{{ tag_name | slugify }}/" class="tag-badge">
          {{ tag_name }} <span class="tag-count">({{ tag_data[1].size }})</span>
        </a>
      {% endif %}
    {% endfor %}
  </div>
</div>

<!-- Services -->
<div class="tag-section">
  <h2 id="services">Services</h2>
  <div class="tag-cloud">
    {% for tag_data in all_tags %}
      {% assign tag_name = tag_data[0] %}
      {% if site.data.tag_groups.services contains tag_name %}
        <a href="{{ site.baseurl }}/tags/{{ tag_name | slugify }}/" class="tag-badge">
          {{ tag_name }} <span class="tag-count">({{ tag_data[1].size }})</span>
        </a>
      {% endif %}
    {% endfor %}
  </div>
</div>

<!-- Techniques -->
<div class="tag-section">
  <h2 id="techniques">Techniques</h2>
  <div class="tag-cloud">
    {% for tag_data in all_tags %}
      {% assign tag_name = tag_data[0] %}
      {% if site.data.tag_groups.techniques contains tag_name %}
        <a href="{{ site.baseurl }}/tags/{{ tag_name | slugify }}/" class="tag-badge">
          {{ tag_name }} <span class="tag-count">({{ tag_data[1].size }})</span>
        </a>
      {% endif %}
    {% endfor %}
  </div>
</div>

<!-- Other Tags (not in any group) -->
<div class="tag-section">
  <h2 id="other">Other Tags</h2>
  <div class="tag-cloud">
    {% for tag_data in all_tags %}
      {% assign tag_name = tag_data[0] %}
      {% assign in_group = false %}
      
      {% for group in site.data.tag_groups %}
        {% if group[1] contains tag_name %}
          {% assign in_group = true %}
        {% endif %}
      {% endfor %}
      
      {% unless in_group %}
        <a href="{{ site.baseurl }}/tags/{{ tag_name | slugify }}/" class="tag-badge">
          {{ tag_name }} <span class="tag-count">({{ tag_data[1].size }})</span>
        </a>
      {% endunless %}
    {% endfor %}
  </div>
</div>
