import React from 'react';

const SecurityExplanation = ({ issue, onClose }) => {
    if (!issue || !issue.details) return null;

    const { title, explanation, impact, recommendation } = issue.details;

    return (
        <div className="explanation-overlay fadeIn" onClick={onClose}>
            <div className="explanation-card glass-panel" onClick={(e) => e.stopPropagation()}>
                <div className="explanation-header">
                    <h3 className="explanation-title">{title}</h3>
                    <button className="close-btn small" onClick={onClose}>&times;</button>
                </div>
                <div className="explanation-body">
                    <section className="exp-section">
                        <h4>What it means</h4>
                        <p>{explanation}</p>
                    </section>
                    <section className="exp-section">
                        <h4>Why it matters</h4>
                        <p>{impact}</p>
                    </section>
                    <section className="exp-section">
                        <h4>How to fix it</h4>
                        <p>{recommendation}</p>
                    </section>
                </div>
                <div className="explanation-footer">
                    <button className="btn-secondary" onClick={onClose}>Understood</button>
                </div>
            </div>
        </div>
    );
};

export default SecurityExplanation;
